package nestedaes

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/etclab/aes256"
	"github.com/etclab/mu"
)

type PlainHeader struct {
	Size   uint32
	BaseIV []byte // aes256.IVSize
}

type EncryptedHeader struct {
	DataTag []byte   // aes256.TagSize
	DEKs    [][]byte //aes256.KeySize
}

type Header struct {
	PlainHeader
	EncryptedHeader
	//HeaderTag [aes256.TagSize]byte (exists only in encrypted header)
}

// String satisfies the [fmt.Stringer] interface.
func (h *Header) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "{\n")
	fmt.Fprintf(&b, "\tSize: %d,\n", h.Size)
	fmt.Fprintf(&b, "\tBaseIV: %x,\n", h.BaseIV)
	fmt.Fprintf(&b, "\tDataTag: %x,\n", h.DataTag)
	fmt.Fprintf(&b, "\tDEKs (%d): [\n", len(h.DEKs))
	for i := 0; i < len(h.DEKs); i++ {
		fmt.Fprintf(&b, "\t\t%d: %v,\n", i, h.DEKs[i])
	}
	fmt.Fprintf(&b, "\t]\n")
	fmt.Fprintf(&b, "}")

	return b.String()
}

// New creates a new [Header] and initializes the BaseIV, DataTag, and first
// DEK entry.
func NewHeader(iv, dataTag, dek []byte) (*Header, error) {
	h := &Header{}
	if len(iv) != aes256.IVSize {
		return nil, aes256.IVSizeError(len(iv))
	}
	h.BaseIV = make([]byte, aes256.IVSize)
	copy(h.BaseIV, iv)

	if len(dataTag) != aes256.TagSize {
		return nil, aes256.TagSizeError(len(dataTag))
	}
	h.DataTag = make([]byte, aes256.TagSize)
	copy(h.DataTag, dataTag)

	if len(dek) != aes256.KeySize {
		return nil, aes.KeySizeError(len(dek))
	}
	h.DEKs = make([][]byte, 1)
	h.DEKs[0] = make([]byte, aes256.KeySize)
	copy(h.DEKs[0], dek)

	h.Size = uint32(4 + len(h.BaseIV) + len(h.DataTag) + aes256.KeySize + aes256.TagSize) // 4 for the Size field, tagsize for header tag
	return h, nil
}

// AddDEK adds a new data key entry to the header.
func (h *Header) AddDEK(dek []byte) {
	if len(dek) != aes256.KeySize {
		mu.Panicf("%v", aes.KeySizeError(len(dek)))
	}
	h.Size += aes256.KeySize
	h.DEKs = append(h.DEKs, dek)
}

// Marshal marshals the header to a []byte.  As part of marshaling, this method
// takes care of encrypting the "encrypted" portion of the header.
func (h *Header) Marshal(kek []byte) ([]byte, error) {
	if len(kek) != aes256.KeySize {
		return nil, aes.KeySizeError(len(kek))
	}

	if len(h.DEKs) == 0 {
		return nil, fmt.Errorf("header has zero DEKs")
	}

	// write the plaintext data for what will become the encrypted part of the
	// header
	ct := new(bytes.Buffer)
	ct.Write(h.DataTag)
	for _, dek := range h.DEKs {
		ct.Write(dek)
	}

	// encrypt it
	iv := aes256.CopyIV(h.BaseIV)
	aes256.AddIV(iv, len(h.DEKs)-1)

	// encrypt with current KEK
	// TODO: should size or anything else be verified as additional data?
	enc := aes256.EncryptGCM(kek, aes256.IVToNonce(iv), ct.Bytes(), nil)

	// write the plain portion of the header and concatenate the encryption
	// portion
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, h.Size)
	b.Write(h.BaseIV)
	b.Write(enc)

	return b.Bytes(), nil
}

// Unmarshal takes a marshalled version of the header and the current Key
// Encryption Key (KEK) and deserializes and decrypts the header.
func UnmarshalHeader(kek, data []byte) (*Header, error) {
	if len(kek) != aes256.KeySize {
		return nil, aes.KeySizeError(len(kek))
	}

	h := &Header{}
	r := bytes.NewReader(data)

	err := binary.Read(r, binary.BigEndian, &h.Size)
	if err != nil {
		return nil, fmt.Errorf("can't read Size field: %w", err)
	}

	if h.Size != uint32(len(data)) {
		return nil, fmt.Errorf("header size field is %d but marshalled data is %d bytes", h.Size, len(data))
	}

	h.BaseIV = make([]byte, aes256.IVSize)
	n, err := r.Read(h.BaseIV)
	if err != nil {
		return nil, fmt.Errorf("can't read BaseIV: %w", err)
	}
	if n != len(h.BaseIV) {
		return nil, fmt.Errorf("BaseIV field is %d bytes but should be %d", h, len(h.BaseIV))
	}

	enc := data[int(r.Size())-r.Len():]
	mod := (len(enc) - aes256.TagSize - aes256.TagSize) % aes256.KeySize
	if mod != 0 {
		return nil, fmt.Errorf("header has a partial entry")
	}
	numDEKs := (len(enc) - aes256.TagSize - aes256.TagSize) / aes256.KeySize
	if numDEKs <= 0 {
		return nil, fmt.Errorf("header has 0 DEKs")
	}

	iv := aes256.CopyIV(h.BaseIV)
	aes256.AddIV(iv, numDEKs-1)
	dec, err := aes256.DecryptGCM(kek, aes256.IVToNonce(iv), enc, nil)
	h.DEKs = make([][]byte, numDEKs)

	for i := 0; i < numDEKs; i++ {
		h.DEKs[i] = make([]byte, aes256.KeySize)
		n := copy(h.DEKs[i], dec[aes256.TagSize+i*aes256.KeySize:])
		if n != aes256.KeySize {
			return nil, fmt.Errorf("can't read DEK %d/%d", i, numDEKs)
		}
	}

	h.DataTag = make([]byte, aes256.TagSize)
	copy(h.DataTag, dec[:len(h.DataTag)])

	return h, nil
}
