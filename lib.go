package nestedaes

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/etclab/aes256"
	"github.com/etclab/mu"
)

const KeySize = aes256.KeySize

// SplitHeaderPayload takes a nestedaes encrypted slice of bytes and returns
// it's two components: the header bytes and the payload bytes.  If the slice
// is too small to contain a valid heaeder, Split HeaderPayload returns an
// error.
func SplitHeaderPayload(blob []byte) ([]byte, []byte, error) {
	var hSize uint32
	r := bytes.NewReader(blob)
	binary.Read(r, binary.BigEndian, &hSize)

	if hSize > uint32(len(blob)) {
		return nil, nil, fmt.Errorf("header size (%d bytes) is >= blob size (%d bytes)", hSize, len(blob))
	}

	return blob[:int(hSize)], blob[int(hSize):], nil
}

// Encrypt encrypts the plaintext and returns the encrypted blob.  The function
// encrypts the plaintext with a randomly generated Data Encryption Key (KEK),
// and uses the input Key Encryption Key (KEK) to encrypt the DEK in the blob's
// header.  The IV is the BaseIV.  The caller should randomly generate it; each
// subsequent layer of encryption uses a different IV derived from the BaseIV.
// The same IV must never be passed to this function more than once.
//
// Note that this function overwriets the plaintext slice to hold the new
// ciphertext.  On success, the functoin outputs the new blob; otherwise, it
// returns an error.
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

// Reencrypt reencrypts the blob by generating a new random KEK and DEK.  On
// success, the function returns th new blobl and KEK; otherwise, it returns an
// error.
//
// NOte taht this function modifies the input blob slice.
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

// ReencryptWithKeys is the same as [Rencrypt], but it allows the caller to
// specify the new KEK and DEK, rather than having them be randomly generated.
func ReencryptWithKeys(blob, kek, newKEK, newDEK []byte) ([]byte, error) {
	hData, payload, err := SplitHeaderPayload(blob)
	if err != nil {
		return nil, err
	}

	h, err := UnmarshalHeader(kek, hData)
	if err != nil {
		return nil, err
	}

	h.AddDEK(newDEK)

	iv := aes256.CopyIV(h.BaseIV)
	aes256.AddIV(iv, len(h.DEKs)-1)
	aes256.EncryptCTR(newDEK, iv, payload)

	hData, err = h.Marshal(newKEK)
	if err != nil {
		return nil, err
	}
	w := new(bytes.Buffer)
	w.Write(hData)
	w.Write(payload)
	return w.Bytes(), nil
}

// Decrypt performed the nexted decryption of blob.  The function returns the
// plaintext on success; otherwise, it returns an error.  The additionalData
// represents any additionalData passed as part of the original call to
// [Encrypt] which is included in the GCM tag.
//
// Note that this function modifies the blob input parameter.
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
