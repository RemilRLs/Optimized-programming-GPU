# MD4 Hash Cracker (CPU & GPU OpenCL)

## Description

This project implement an MD4 hash cracker that can run both on CPU or GPU using OpenCL. The goal is to efficiently brute-force passwords and compare their hashes against a given target MD4 hash

By leveraging GPU acceleration the program achieve significant performance improvements over a traditional CPU-based implementation

## Installation & Compilation

* GCC / Clang (for CPU version)
* OpenCL
* Make
* A compatible GPU that supports OpenCL

## Usage

### CPU Mode

./simple/simple <md4_target>

### GPU Mode

./simple/gpu <md4_target>

## Example Output

```
[+] - Match found!
[+] - Password: ouioui
[+] - Computed Hash: 3663e1018c8f6b84deb45bbae2bb7813
[>] - Target Hash:   3663e1018c8f6b84deb45bbae2bb7813

Execution Time: 13.9s
``` 
