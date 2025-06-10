# nestedaes

Go module that implements updatable re-encryption using nested AES based on the
ASIACRYPT '20 paper ["Improving Speed and Security in Updatable Encryption
Schemes"](https://eprint.iacr.org/2020/222.pdf) by Boneh et al.  This module
specifically implements the scheme from section 4.1 of that ("A Simple Nested
Construction"), which requires only a nested application of a
symmetric, authenticated encryption cipher.  This module uses AES-GCM for its
implementation.


# Building

Although the module is intended as library, it includes a command-line utility
called `nestedaes` that demonstrates the major algorithms.  To build the
command-line utility, enter:

```
make
```

Invoking `nestedaes` with the `-h` or `--help` option provides a detailed usage
statement.


# Unit Testing

To run all unit tests, enter:

```
make test
```

# Benchmarking

To run the benchmarks, enter:

```
make benchmarking
```

The benchmarks measure the time to nested-decrypt a file, varying the size of
the file and the number of layers of encryption.
