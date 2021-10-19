# byol

Learning project to get familiar with the PE format, as well as to have a shellcode loader for reversing purposes.

You can read [this](https://visit.suspect.network/reversing-adventures/building-a-pe-from-scratch) blogpost if you're interested in the learning process.

Currently only supports x86.

## Usage

You can use the script in basically a couple different ways:

Load shellcode from a file, write it to a .exe:

```sh
python3 byol.py --infile test.bin --outfile shellcode.exe
```

Load shellcode from a hexstring, write it to a .exe:

```sh
python3 byol.py --shellcode 9090909090909090909090 --outfile shellcode.exe
```

Load shellcode from a file, or from hexstring and attach x64dbg:

```sh
python3 byol.py --shellcode 9090909090909090909090 --outfile shellcode.exe --debug C:\Users\user\Desktop\x32dbg.exe
```

To cleanup the created .exe file, simply add the `--cleanup` flag.

## TODO

* Add x64 support
