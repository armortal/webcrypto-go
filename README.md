# webcrypto-go [![test](https://github.com/armortal/webcrypto-go/actions/workflows/test.yaml/badge.svg)](https://github.com/armortal/webcrypto-go/actions/workflows/test.yaml)

An implementation of the W3C Web Cryptography API specification (https://www.w3.org/TR/WebCryptoAPI/) for Go using Go's standard `crypto` library.

> [!IMPORTANT]  
> Whilst we try to ensure that we don't commit breaking changes until we release our first stable version, there
> may be times where decisions made during early development no longer make sense and therefore require
> breaking changes. Please be mindful of this when updating your version of this library until we hit v1.0.0.

## Contents

- [Background](#background)
- [Implementation status](#implementation-status)
- [Getting started](#getting-started)
- [Algorithms](#algorithms)
	- [ECDSA](#ecdsa)
	- [HMAC](#hmac)
	- [RSA-OAEP](#rsa-oaep)
	- [SHA](#sha)
- [Contributing](#contributing)

## Background

The Web Cryptography API is an open standard developed by the W3C and *"defines a low-level interface to interacting with cryptographic key material that is managed or exposed by user agents"* (https://www.w3.org/TR/WebCryptoAPI/).

Although the Web Cryptography API was developed for JavaScript, the way we use cryptographic functions in applications across programming languages is unique to the language itself. This library aims to keep these operations consistent across languages so that developers can use documentation and knowledge from a well known open-standard to develop their applications easily and consistently. Cryptography is hard, and we hope this library can help all developers on their cryptographic journey.

The documentation and references used throughout this library come from the amazing authors at:
- [W3C Web Cryptography API Specification](https://www.w3.org/TR/WebCryptoAPI/)
- [Mozilla Web Crypto API Docs](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

## Implementation status

This library is still in active development and all algorithms are not yet supported. While we continue working on implementations that we think are priority, we welcome feedback and contributions from our open-source community. Below are algorithms and their usages that have been implemented.

| Algorithm | encrypt | decrypt | sign | verify | digest | generateKey | deriveKey | deriveBits | importKey | exportKey | wrapKey | unwrapKey | 
| :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | 
| [HMAC](#hmac) |||:white_check_mark:|:white_check_mark:||:white_check_mark:|||:white_check_mark:|:white_check_mark:|||
| [RSA-OAEP](#rsa-oaep) |:white_check_mark:|:white_check_mark:||||:white_check_mark:|||:white_check_mark:|:white_check_mark:|||
| [SHA](#sha) |||||:white_check_mark:||||||||

## Getting started

`go get github.com/armortal/webcrypto-go`

## Algorithms

### ECDSA

The **ECDSA** algorithm is the implementation of operations described in [§23](https://www.w3.org/TR/WebCryptoAPI/#ecdsa) of the W3C specification.

```go
package main

import (
	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/ecdsa"
)

func main() {
	// generate a new ECDSA key
	key, err := webcrypto.Subtle().GenerateKey(
		&ecdsa.Algorithm{
			NamedCurve: "P-256"
		}, true, webcrypto.Sign, webcrypto.Verify)
	if err != nil {
		panic(err)
	}
}
```

### HMAC

The **HMAC** algorithm is the implementation of operations described in [§29](https://www.w3.org/TR/WebCryptoAPI/#hmac) of the W3C specification.

```go
package main

import (
	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/hmac"
)

func main() {
	// Generate a new key. A *hmac.CryptoKey is returned which implements webcrypto.CryptoKey
	key, err := webcrypto.Subtle().GenerateKey(
		&hmac.Algorithm{
			KeyGenParams: &hmac.KeyGenParams{
				Hash: "SHA-256",
			},
		}, true, webcrypto.Sign, webcrypto.Verify)

	cryptokey := key.(webcrypto.CryptoKey)

	// Sign some data. Note that this library uses io.Reader to pass bytes of data.
	sig, err := webcrypto.Subtle().Sign(
		&hmac.Algorithm{}, cryptokey, bytes.NewReader([]byte("helloworld")))

	// Verify the signature
	ok, err := webcrypto.Subtle().Verify(
		&hmac.Algorithm{}, cryptokey, sig, bytes.NewReader([]byte("helloworld")))

	// Export the key as *webcrypto.JsonWebKey
	out, err := webcrypto.Subtle().ExportKey(webcrypto.Jwk, cryptoKey)
	jwk := out.(*webcrypto.JsonWebKey)

	// Export the key as raw bytes
	out, err := webcrypto.Subtle().ExportKey(webcrypto.Raw, cryptoKey)
	raw := out.([]byte)

	// Import a JsonWebKey
	in, err := webcrypto.Subtle().ImportKey(
		webcrypto.Jwk, 
		jwk, 
		&hmac.Algorithm{
			ImportParams: &hmac.ImportParams{
				Hash: "SHA-256",
			},
		}, 
		true, 
		webcrypto.Sign, webcrypto.Verify)

	// Import a key from raw bytes
	in, err := webcrypto.Subtle().ImportKey(
		webcrypto.Raw, 
		raw, 
		&hmac.Algorithm{
			ImportParams: &hmac.ImportParams{
				Hash: "SHA-256",
			},
		}, 
		true, 
		webcrypto.Sign, webcrypto.Verify)
}
```

### RSA-OAEP

The **RSA-OAEP** algorithm is the implementation of operations described in [§22](https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep) of the W3C specification.

```go
package main

import (
	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/rsa"
)

func main() {
	// generateKey
	key, err := webcrypto.Subtle().GenerateKey(
		&rsa.Algorithm{
			Name: "RSA-OAEP",
			HashedKeyGenParams: &rsa.HashedKeyGenParams{
				KeyGenParams: rsa.KeyGenParams{
					ModulusLength: 2048,
					PublicExponent:      *big.NewInt(65537),
				},
				Hash: "SHA-256",
			},

		}, true, webcrypto.Decrypt, webcrypto.Encrypt)

	if err != nil {
		panic(err)
	}

	cryptoKeyPair := key.(webcrypto.CryptoKeyPair)

	// do something with cryptoKeyPair
}
```

## SHA

The **SHA** algorithm is the implementation of operations described in [§30](https://www.w3.org/TR/WebCryptoAPI/#sha) of the W3C specification.

The implementation in this library uses Go's `io.Reader` as the input to the `digest` method.

```go
package main

import (
	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/sha"
)

func main() {
	// digest
	hash, err := webcrypto.Subtle().Digest(
		&sha.Algorithm{
			Name: "SHA-256",
		}, bytes.NewReader([]byte("helloworld")))

	if err != nil {
		panic(err)
	}

	// do something with hash
}
```


## Contributing

If you have found a bug or would like to see new features, please create a new issue in this repository. If there is an issue that poses a security risk, please refrain from posting the issue publicly and contact [support@armortal.com](mailto://support@armortal.com) instead.