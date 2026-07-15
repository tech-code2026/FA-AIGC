## Fully Anonymous Stateless Communication for AIGC Copyright Management

This project presents fully decentralized and trusted AIGC copyright management scheme using Golang.

## Pre-requisites

* `Golang`  https://go.dev/dl/   

## File description
* `crypto`  The folder includes detailed implementation of Shamir SS and AIGC scheme.
* `crypto/ss` The file implements the related functions of secret sharing.
* `crypto/aigc` The file implements the related functions of AIGC scheme.
* `bn128`  The folder contains the source codes of curve BN128.
* `main.go`   Run this file to test the functionalities of the framework.


## How to run

1. Generate private keys to generate the `.env` file

   ```bash
   bash genPrvKey.sh
   ```

2. start ganache

   ```bash
   ganache-cli --mnemonic "aigc" -l 90071992547 -e 1000
   ```

3. Compile the smart contract code

   ```bash
   cd compile
   bash compile.sh
   ```

4. Run the main.go

    ```bash
    go run main.go
    ```

5. How to test aigc.go

    ```bash
    cd crypto/aigc
    go test -v
    ```

6. How to test ss.go
    ```bash
    cd crypto/ss
    go test -v
    ```

