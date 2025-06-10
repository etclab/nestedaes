# nestedaes

Go module that implements updatable re-encryption using nested AES based on the
ASIACRYPT'20 paper "Improving Speed and Security in Updatable Encryption
Schemes" by Boneh et al.


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

To run the unit tests, enter:

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
