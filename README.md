## Running

The following generates one syzkaller program per verifier selftest (from `verifier/`).
The first and only argument is the output directory.
```
gcc -o convert convert.c
./convert /path/to/syzkaller/sys/linux/test/
```
The output will list selftests that were skipped and the reasons.
The number of syscalls that are expected to fail is also displayed.

## License

This project is under GPL v2.0.
