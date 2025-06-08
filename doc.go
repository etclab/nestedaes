// Package nestedaes implements an updatable encryption scheme from:
//
//	Dan Boneh, Saba Eskandarian, Sam Kim, and Maurice Shih.
//	"Improving Speed and Security in Updatable Encryption Schemes."
//	In International Conference on the Theory and Application of Cryptology and Information Security (ASIACRYPT), 2020.
//
// The package specifically implements the scheme from section 4.1 of that
// [paper] ("A Simple Nested Construction"), which requires only a nested
// application of a symmetric, authenticated encryption cipher.  This package
// uses AES-GCM for its implementaion.
//
// # Format
//
// We use the term "blob" to refer to the nested encrypted plaintext "payload", along
// with the ciphertext header.  Specifically, using || to denote concatenation,
// the format of a blob is:
//
//	BLOB := HEADER || PAYLOAD
//	HEADER := PLAIN_HEADER || ENCRYPTED_HEADER
//	PLAIN_HEADER := SIZE || IV
//	ENCRYPTED_HEADER := DATATAG || DEKS...
//
// Where DATATAG is the GCM tag for the first layer of encryption, and DEKS...
// is the list of DEKS (one DEK per layer of encryption).

// [paper]: https://eprint.iacr.org/2020/222.pdf
package nestedaes
