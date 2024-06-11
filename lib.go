// The format of a blob is:
//
//	BLOB := HEADER || PAYLOAD
//	HEADER := PLAIN_HEADER || ENCRYPTED_HEADER
//	PLAIN_HEADER := SIZE || IV
//	ENCRYPTED_HEADER := TAG || ENTRIES...
//	ENTRY := KEK || DEK
//
// The PAYLOAD is encrypted plaintext.
package nestedaes

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/etclab/aes256"
	"github.com/etclab/mu"
)

const KeySize = aes256.KeySize

// SplitHeaderPayload takes a slice of the Blob of returns
// it's two components: the Header bytes and the Payload bytes.
func SplitHeaderPayload(blob []byte) ([]byte, []byte, error) {
	var hSize uint32
	r := bytes.NewReader(blob)
	binary.Read(r, binary.BigEndian, &hSize)

	if hSize >= uint32(len(blob)) {
		return nil, nil, fmt.Errorf("header size (%d bytes) is >= blob size (%d bytes)", hSize, len(blob))
	}

	return blob[:int(hSize)], blob[int(hSize):], nil
}

// Encrypt encrypts the plaintext and returns the Blob.  The function encrypts
// the plaintext with a randomly generated Data Encryptoin Key (KEK), and uses
// the input Key Encryption Key (KEK) to encrypt the DEK in the Blob's header.
// The IV is the BaseIV.  The caller should randomly generate it; each
// subsequent layer of encryption uses a different IV derived from the BaseIV.
// The same IV must never be passed to this function more than once.
// TODO: does Encrypt modify the plaintext input?
func Encrypt(plaintext, kek, iv, additionalData []byte) ([]byte, error) {
	// encrypt the plaintext
	dek := aes256.NewRandomKey()
	nonce := aes256.NewZeroNonce()
	payload := aes256.EncryptGCM(dek, nonce, plaintext, additionalData)

	// separate the ciphertext from the AEAD tag
	payload, tag, err := aes256.SplitCiphertextTag(payload)
	if err != nil {
		mu.Panicf("nestedaes.Encrypt: %v", err)
	}

	// create the ciphertext header
	h, err := NewHeader(iv, tag, dek)
	if err != nil {
		return nil, err
	}

	// concat header and payload
	hData, err := h.Marshal(kek)
	if err != nil {
		return nil, err
	}
	w := new(bytes.Buffer)
	w.Write(hData)
	w.Write(payload)
	return w.Bytes(), nil
}

// output: new blob, new kek, error
// TODO: does Rencrypt modify the blob and kek inputs?
func Reencrypt(blob, kek []byte) ([]byte, []byte, error) {
	hData, payload, err := SplitHeaderPayload(blob)
	if err != nil {
		return nil, nil, err
	}

	h, err := UnmarshalHeader(kek, hData)
	if err != nil {
		return nil, nil, err
	}

	newKEK := aes256.NewRandomKey()
	newDEK := aes256.NewRandomKey()
	h.AddDEK(newDEK)

	iv := aes256.CopyIV(h.BaseIV)
	aes256.AddIV(iv, len(h.DEKs)-1)
	aes256.EncryptCTR(newDEK, iv, payload)

	hData, err = h.Marshal(newKEK)
	if err != nil {
		return nil, nil, err
	}
	w := new(bytes.Buffer)
	w.Write(hData)
	w.Write(payload)
	return w.Bytes(), newKEK, nil
}

// decrypted payload, and error
// TODO: does Decrypt modify the blob and kek inputs?
func Decrypt(blob, kek []byte, additionalData []byte) ([]byte, error) {
	hData, payload, err := SplitHeaderPayload(blob)
	if err != nil {
		return nil, err
	}

	h, err := UnmarshalHeader(kek, hData)
	if err != nil {
		return nil, err
	}

	iv := aes256.CopyIV(h.BaseIV)
	aes256.AddIV(iv, len(h.DEKs)-1) // fast-forward to largest IV

	i := len(h.DEKs) - 1
	for i > 0 {
		dek := h.DEKs[i]
		aes256.DecryptCTR(dek, iv, payload)
		aes256.DecIV(iv)
		i--
	}

	dek := h.DEKs[i]
	nonce := aes256.NewZeroNonce()
	payload = append(payload, h.DataTag...)
	plaintext, err := aes256.DecryptGCM(dek, nonce, payload, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
