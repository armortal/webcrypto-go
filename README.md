# webcrypto-go
An implementation of the W3C Web Cryptography API specification (https://www.w3.org/TR/WebCryptoAPI/) for Go.

## Contents

- [Background](#background)
- [Implementation status](#implementation-status)
- [Getting started](#getting-started)
- [Algorithms](#algorithms)
	- [HMAC](#hmac)
	- [RSA-OAEP](#rsa-oaep)
		- [generateKey](#generatekey)

- [Examples](#examples)

## Background

The Web Cryptography API is an open standard developed by the W3C and *"defines a low-level interface to interacting with cryptographic key material that is managed or exposed by user agents"* (https://www.w3.org/TR/WebCryptoAPI/).

Although the Web Cryptography API was developed for front-end applications, the way cryptographic logic is implemented in applications across languages is unique to the language itself. This library aims to keep these operations consistent across languages, in this case Golang, so that users can use documentation and knowledge from a well known open-standard to develop their applications easily and consistently. Cryptography is hard, and we hope this library can help all developers on their cryptographic journey.

The documentation and references used throughout this library come from the amazing authors at:
- [W3C Web Cryptography API Specification](https://www.w3.org/TR/WebCryptoAPI/)
- [Mozilla Web Crypto API Docs](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

## Implementation status

This library is still in active development and all algorithms are not yet supported. While we continue working on implementations that we think are priority, we welcome feedback and contributions from our open-source community. Below are algorithms and their usages that have been implemented.

| Algorithm | encrypt | decrypt | sign | verify | digest | generateKey | deriveKey | deriveBits | importKey | exportKey | wrapKey | unwrapKey | 
| :---------------------: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | 
| **HMAC** |||:white_check_mark:|:white_check_mark:||:white_check_mark:|||:white_check_mark:|:white_check_mark:|||
| **RSA-OAEP** ||||||:white_check_mark:|||||||
| **SHA** |||||:white_check_mark:||||||||

## Getting started

`go get github.com/armortal/webcrypto-go`

## Algorithms

### HMAC

```go
package main

import (
	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/hmac"
	"github.com/armortal/webcrypto-go/algorithms/sha256"
)

func main() {
	key, err := webcrypto.Subtle().GenerateKey(
		hmac.New(hmac.WithHash(sha256.New())), true, webcrypto.Sign, webcrypto.Verify)

	if err != nil {
		panic(err)
	}

	cryptokey := key.(webcrypto.CryptoKey)

	// do something with cryptoKey
}
```

### RSA-OAEP

The [RSA-OAEP](https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep) algorithm can be used by importing `github.com/armortal/webcrypto-go/algorithms/rsa`. The following shows the RSA-OAEP objects that are used in this library.

| Operation	| Parameters | Result |
| :-------- | :--------- | :----- |
| encrypt | `rsa.OaepParams`	| `[]byte` |
| decrypt| `rsa.OaepParams` | `[]byte` |
| [generateKey](#generatekey) | `rsa.HashedKeyGenParams` | `webcrypto.CryptoKeyPair` |
| importKey	| `rsa.RsaHashedImportParams` | `webcrypto.CryptoKey` |
| exportKey | None | `webcrypto.JsonWebKey`, `[]byte` |

#### generateKey

```go
package main

import (
	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/rsa"
)

func main() {
	key, err := webcrypto.Subtle().GenerateKey(
		&rsa.HashedKeyGenParams{
			KeyGenParams: rsa.KeyGenParams{
				Name:          "RSA-OAEP",
				ModulusLength: 2048,
				Exponent:      *big.NewInt(65537),
			},
			Hash: "SHA-256",
		}, true, webcrypto.Decrypt, webcrypto.Encrypt

	if err != nil {
		panic(err)
	}

	ckp := key.(webcrypto.CryptoKeyPair)

	// do something with ckp (CryptoKeyPair)
}
```

## Contributing

If you have found a bug or would like to see new features, please create a new issue in this repository. If there is an issue that poses a security risk, please refrain from posting the issue publicly and contact [support@armortal.com](mailto://support@armortal.com) instead.