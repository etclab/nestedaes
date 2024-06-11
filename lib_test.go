package nestedaes

import (
	"bytes"
	"testing"

	"github.com/etclab/aes256"
)

func TestEncryptOnce(t *testing.T) {
	plain := []byte("The quick brown fox jumps over the lazy dog.")

	kek := aes256.NewRandomKey()
	iv := aes256.NewRandomIV()
	blob, err := Encrypt(plain, kek, iv, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Decrypt(blob, kek, nil)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(plain, got) != 0 {
		t.Fatalf("expected decrypt to produce %x, got %x", plain, got)
	}
}

func TestReencryptOnce(t *testing.T) {
	plain := []byte("The quick brown fox jumps over the lazy dog.")

	kek := aes256.NewRandomKey()
	iv := aes256.NewRandomIV()
	blob, err := Encrypt(plain, kek[:], iv[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	blob, kek, err = Reencrypt(blob, kek[:])
	if err != nil {
		t.Fatal(err)
	}

	got, err := Decrypt(blob, kek[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(plain, got) != 0 {
		t.Fatalf("expected decrypt to produce %x, got %x", plain, got)
	}
}

func TestReencryptMany(t *testing.T) {
	plain := []byte("The quick brown fox jumps over the lazy dog.")

	kek := aes256.NewRandomKey()
	iv := aes256.NewRandomIV()
	blob, err := Encrypt(plain, kek[:], iv[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		blob, kek, err = Reencrypt(blob, kek[:])
		if err != nil {
			t.Fatalf("reencrypt #%d failed: %v", i, err)
		}
	}

	got, err := Decrypt(blob, kek[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(plain, got) != 0 {
		t.Fatalf("expected decrypt to produce %x, got %x", plain, got)
	}
}
