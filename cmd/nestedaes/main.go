package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/etclab/aes256"
	"github.com/etclab/mu"
	"github.com/etclab/nestedaes"
)

const usage = `Usage: nestedaes [options] FILE

Encrypt/decrypt a file using nested AES.

positional arguments:
  FILE
    The file to encrypt, re-encrypt, or decrypt
    
options:
  -op OPERATION
    OPERATION must either "encrypt", "reencrypt" or "decrypt"

    Default: encrypt

  -out OUT_FILE      
    The output file for the operation.  If not given, then the modifications
    are done on the input FILE

  -inkek INPUT_KEK_FILE
    The key-encrypting key file.
      Must be specified for -reencrypt and -decrypt.
      Must not be specified for -encrypt.

    Default: kek.key

  -outkek OUTPUT_KEK_FILE
    The output key-encrypting key file.  The new KEK is written to this file.
    If this is the same as -in-kek, the file is overwritten.
      Must be specified for -encrypt and -reencrypt.
      Must not be specified for -decrypt.

    Default: kek.key

  -h|-help
    Display this usage statement and exit.

examples:
  $ nestedaes -op encrypt -outkek kek.key -out foo.enc foo.txt
  $ nestedaes -op reencrypt -inkek kek.key -outkek kek2.key -out foo.renc foo.enc
  $ nestedaes -op decrypt -inkek kek2.key -out foo.txt foo.renc
`

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s", usage)
}

type Options struct {
	// positional
	inFile string
	// optional
	op      string
	outFile string
	inKEK   string
	outKEK  string
}

func parseOptions() *Options {
	opts := Options{}

	flag.Usage = printUsage
	flag.StringVar(&opts.op, "op", "encrypt", "")
	flag.StringVar(&opts.outFile, "out", "", "")
	flag.StringVar(&opts.inKEK, "inkek", "kek.key", "")
	flag.StringVar(&opts.outKEK, "outkek", "kek.key", "")

	flag.Parse()

	if flag.NArg() != 1 {
		mu.Fatalf("expected one positional argument but got %d", flag.NArg())
	}
	opts.inFile = flag.Arg(0)

	if opts.op != "encrypt" && opts.op != "reencrypt" && opts.op != "decrypt" {
		mu.Fatalf("invalid value for -op; must be \"encrypt\", \"reencrypt\", or \"decrypt\"")
	}

	if opts.outFile == "" {
		opts.outFile = opts.inFile
	}

	return &opts
}

func doEncrypt(inFile, outFile, outKEK string) {
	plaintext, err := os.ReadFile(inFile)
	if err != nil {
		mu.Fatalf("encrypt failed: can't read input file: %v", err)
	}

	kek := aes256.NewRandomKey()
	iv := aes256.NewRandomIV()
	blob, err := nestedaes.Encrypt(plaintext, kek, iv, nil)
	if err != nil {
		mu.Fatalf("encrypt failed: %v", err)
	}

	err = os.WriteFile(outFile, blob, 0660)
	if err != nil {
		mu.Fatalf("encrypt failed: can't write output file: %v", err)
	}

	err = os.WriteFile(outKEK, kek[:], 0660)
	if err != nil {
		mu.Fatalf("encrypt failed: can't write KEK file: %v", err)
	}
}

func doReencrypt(inFile, outFile, inKEK, outKEK string) {
	blob, err := os.ReadFile(inFile)
	if err != nil {
		mu.Fatalf("can't read input file: %v", err)
	}

	kek, err := os.ReadFile(inKEK)
	if err != nil {
		mu.Fatalf("can't read input KEK file: %v", err)
	}

	newBlob, newKEK, err := nestedaes.Reencrypt(blob, kek)
	if err != nil {
		mu.Fatalf("reencrypt failed: %v", err)
	}

	err = os.WriteFile(outFile, newBlob, 0660)
	if err != nil {
		mu.Fatalf("can't write output file: %v", err)
	}

	err = os.WriteFile(outKEK, newKEK[:], 0660)
	if err != nil {
		mu.Fatalf("can't write KEK file: %v", err)
	}
}

func doDecrypt(inFile, outFile, inKEK string) {
	blob, err := os.ReadFile(inFile)
	if err != nil {
		mu.Fatalf("can't read input file: %v", err)
	}

	kek, err := os.ReadFile(inKEK)
	if err != nil {
		mu.Fatalf("can't read input KEK file: %v", err)
	}

	plaintext, err := nestedaes.Decrypt(blob, kek, nil)
	if err != nil {
		mu.Fatalf("decrypt failed: %v", err)
	}

	err = os.WriteFile(outFile, plaintext, 0660)
	if err != nil {
		mu.Fatalf("can't write output file: %v", err)
	}
}

func main() {
	opts := parseOptions()

	switch opts.op {
	case "encrypt":
		doEncrypt(opts.inFile, opts.outFile, opts.outKEK)
	case "reencrypt":
		doReencrypt(opts.inFile, opts.outFile, opts.inKEK, opts.outKEK)
	case "decrypt":
		doDecrypt(opts.inFile, opts.outFile, opts.inKEK)
	default:
		mu.BUG("invalid value for op: %s", opts.op)
	}
}
