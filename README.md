# nestedaes

Go module that implements updatable re-encryption using nested AES based on the
ASIACRYPT'20 paper ["Improving Speed and Security in Updatable Encryption
Schemes"](https://eprint.iacr.org/2020/222.pdf) by Boneh et al.  This module
specifically implements the scheme from section 4.1 of that ("A Simple Nested
Construction"), which requires only a nested application of a
symmetric, authenticated encryption cipher.  This module uses AES-GCM for its
implementaion.

# Building, Testing, and Benchmarking

The nestedaes module is primarily a package (`nestedaes`) that other projects
can use like a library.  However, invoking `make` builds a command-line
executable (also called `nestedaes`) that allows for nested-encrypting and
-decrypting a file.

To run all unit tests, enter:

```
make test
```

To run all benchmarks, enter:

```
make benchmarking
```

Currently, there is only one benchmark, which reports the time to
nested-decrypt a file, varying the size of the file and the number of layers of
encryption.
