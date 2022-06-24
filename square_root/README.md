# Zokrates program to prove knowledge of a square root

- From tutorial https://zokrates.github.io/introduction.html
- The program is in `root.zok`
- Run `zokrates compile -i root.zok` to compile
- Run `zokrates setup` to perform initial setup, which produces `proving.key` and `verification.key`
- Run `zokrates compute-witness -a 337 113569` to apply the program on specific inputs and output a witness file `witness`
- Run `zokrates generate-proof` to generate a proof in `proof.json` file
- Run `zokrates export-verifier` to generate a verifier `verifier.sol` in Solidity
- Run `zokrates verify` to perform verification
