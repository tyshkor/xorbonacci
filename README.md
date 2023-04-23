# Xorbonacci

This repo includes a circuit in Halo2 for Xorbonacci function defined as follows:

* F(0) = 1
* F(1) = 1
* F(n) = F(n - 1) XOR F(n - 2) + n

## Instruction

Compile the repo

```bash
cargo build
```

Run tests

```bash
cargo test
```
