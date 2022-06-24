# Zokrates program to prove knowledge of a square root

- From tutorial https://zokrates.github.io/introduction.html
- We use `sha256packed` from the Zokrates standard library.
- The program is in `hashexample.zok`
- Run `zokrates compile -i hashexample.zok` to compile
- Run `zokrates setup` to perform initial setup, which produces `proving.key` and `verification.key`
- Run `zokrates compute-witness -a 0 0 0 5` to apply the program on specific inputs and output a witness file `witness`
- Run `zokrates generate-proof` to generate a proof in `proof.json` file
- Run `zokrates export-verifier` to generate a verifier `verifier.sol` in Solidity
- Run `zokrates verify` to perform verification
