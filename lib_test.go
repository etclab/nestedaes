package nestedaes

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/etclab/aes256"
)

const (
	KiB     = 1024
	MiB     = 1024 * 1024
	BufSize = 4096
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

func createFileOfSizeB(b *testing.B, path string, size int) {
	f, err := os.Create(path)
	if err != nil {
		b.Fatalf("can't create file %q", path)
	}
	defer f.Close()

	buf := make([]byte, BufSize)

	var written int
	for written < size {
		n := BufSize
		if (size - written) < BufSize {
			n = size - written
		}

		if _, err := rand.Read(buf[:n]); err != nil {
			b.Fatalf("rand.Read failed: %v", err)
		}

		if _, err := f.Write(buf[:n]); err != nil {
			b.Fatalf("write to file %q failed %v", path, err)
		}

		written += n
	}
}

// returns kek
func encryptFile(b *testing.B, path string, layers int) []byte {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		b.Fatalf("can't read file %q: %v", path, err)
	}

	kek := aes256.NewRandomKey()
	iv := aes256.NewRandomIV()

	blob, err := Encrypt(plaintext, kek, iv, nil)
	if err != nil {
		b.Fatalf("encrypt failed: %v", err)
	}

	for i := 2; i <= layers; i++ {
		blob, kek, err = Reencrypt(blob, kek)
		if err != nil {
			b.Fatalf("reencrypt failed: %v", err)
		}
	}

	err = os.WriteFile(path, blob, 0660)
	if err != nil {
		b.Fatalf("can't write output file: %v", err)
	}

	return kek
}

func BenchmarkDecrypt(b *testing.B) {
	tempDir := b.TempDir()
	encLayers := [...]int{1, 10, 50, 100}
	fileSizes := [...]int{
		10 * KiB,
		100 * KiB,
		MiB,
		10 * MiB,
		100 * MiB,
	}

	for _, fileSize := range fileSizes {
		for _, layers := range encLayers {
			b.Run(fmt.Sprintf("Decrypt/size:%d/layers:%d", fileSize, layers), func(b *testing.B) {
				path := filepath.Join(tempDir, fmt.Sprintf("testfile-%d-%d.dat", fileSize, layers))
				createFileOfSizeB(b, path, fileSize)
				kek := encryptFile(b, path, layers)
				for b.Loop() {
					// The Decrypt function modifies the blob (it's an inout
					// parameter: on input it has the ciphertext; on output the
					// plaintext.  Tjhus, we need to read the ciphertext file
					// anew on each iteration, but not time the file I/O.
					b.StopTimer()
					blob, err := os.ReadFile(path)
					if err != nil {
						b.Fatalf("can't read input file: %v", err)
					}
					b.StartTimer()
					_, err = Decrypt(blob, kek, nil)
					if err != nil {
						b.Fatalf("nestedaes.Decrypt failed: %v", err)
					}
				}
			})
		}
	}
}
