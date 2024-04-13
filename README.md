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
		- [Parameter Definitions](#parameter-definitions)
		- [Examples](#examples)
	- [HMAC](#hmac)
	- [RSA-OAEP](#rsa-oaep)
	- [SHA](#sha)
- [Contributing](#contributing)
- [Appendix](#appendix)
	- [Hash Algorithms](#hash-algorithms)

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
| [ECDSA](#ecdsa) |||:white_check_mark:|:white_check_mark:||:white_check_mark:|||:white_check_mark:|:white_check_mark:|||
| [HMAC](#hmac) |||:white_check_mark:|:white_check_mark:||:white_check_mark:|||:white_check_mark:|:white_check_mark:|||
| [RSA-OAEP](#rsa-oaep) |:white_check_mark:|:white_check_mark:||||:white_check_mark:|||:white_check_mark:|:white_check_mark:|||
| [SHA](#sha) |||||:white_check_mark:||||||||

## Getting started

`go get github.com/armortal/webcrypto-go`

## Algorithms

When passing algorithm params into subtle functions, we use the `webcrypto.Algorithm` struct. It has the following properties:

| Field | Type | Description |
| :---- | :--- | :---------- |
| Name | `string` | The algorithm name. |
| Params | `any` | The algorithm parameters as defined by the parameters described by that algorithm in the WebCrypto specification. |

See specific algorithms for the parameter types to be passed in.

### ECDSA

The **ECDSA** algorithm is the implementation of operations described in [§23](https://www.w3.org/TR/WebCryptoAPI/#ecdsa) of the W3C specification. You can import it into your program with `import "github.com/armortal/webcrypto-go/algorithms/ecdsa"`.

#### Parameter Definitions

Below are the parameters that supported ECDSA operations will take according to 
[§23.2](https://www.w3.org/TR/WebCryptoAPI/#ecdsa-registration).

##### Params

As specified in [§23.3](https://www.w3.org/TR/WebCryptoAPI/#EcdsaParams-dictionary)

| Field | Type | Description |
| :---- | :--- | :---------- |
| Hash | `string` | The hash algorithm to use. See the supported [hash algorithms](#hash-algorithms) |

##### KeyGenParams

As specified in [§23.4](https://www.w3.org/TR/WebCryptoAPI/#EcKeyGenParams-dictionary)

| Field | Type | Description |
| :---- | :--- | :---------- |
| NamedCurve | `string` | A valid named curve. One of `P-256`, `P-384`, or `P-521`. |

##### KeyImportParams

As specified in [§23.6](https://www.w3.org/TR/WebCryptoAPI/#EcKeyImportParams-dictionary)

| Field | Type | Description |
| :---- | :--- | :---------- |
| NamedCurve | `string` | A valid named curve. One of `P-256`, `P-384`, or `P-521`. |

#### Examples

```go
package main

import (
	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/ecdsa"
)

func main() {
	// generate a new P-256 ECDSA key
	key, err := webcrypto.Subtle().GenerateKey(
		&webcrypto.Algorithm{
			Name: "ECDSA",
			Params: &ecdsa.KeyGenParams{
				NamedCurve: "P-256",
			},
		}, true, []webcrypto.KeyUsage{
			webcrypto.Sign,
			webcrypto.Verify,
		})
	if err != nil {
		panic(err)
	}

	// key returned is a webcrypto.CryptoKeyPair
	ckp := key.(webcrypto.CryptoKeyPair)

	// sign some data with the private key
	sig, err := webcrypto.Subtle().Sign(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &ecdsa.Params{
			Hash: "SHA-256",
		},
	}, ckp.PrivateKey(), []byte("test"))
	if err != nil {
		panic(err)
	}

	// verify the signature with the public key
	ok, err := webcrypto.Subtle().Verify(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &ecdsa.Params{
			Hash: "SHA-256",
		},
	}, ckp.PublicKey(), sig, []byte("test"))
	if err != nil {
		panic(err)
	}

	if !ok {
		// didn't verify - do something
	}

	// export the public/private key as webcrypto.JsonWebKey
	out, err := webcrypto.Subtle().ExportKey(webcrypto.Jwk, ckp.PrivateKey())
	if err != nil {
		panic(err)
	}

	jwk := out.(webcrypto.JsonWebKey)

	// do something with jwk

	// import a public/private key
	ck, err := webcrypto.Subtle().ImportKey(webcrypto.Jwk, jwk, &webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &ecdsa.KeyImportParams{
			NamedCurve: "P-256",
		},
	}, true, []webcrypto.KeyUsage{
		webcrypto.Sign,
	})
	if err != nil {
		panic(err)
	}

	// do something with the imported webcrypto.CryptoKey
}
```

### HMAC

The **HMAC** algorithm is the implementation of operations described in [§29](https://www.w3.org/TR/WebCryptoAPI/#hmac) of the W3C specification. You can import it into your program with `import "github.com/armortal/webcrypto-go/algorithms/hmac"`.

#### Parameter Definitions

Below are the parameters that supported HMAC operations will take according to 
[§29.2](https://www.w3.org/TR/WebCryptoAPI/#hmac-registration).

##### KeyGenParams

As specified in [§29.5](https://www.w3.org/TR/WebCryptoAPI/#hmac-keygen-params)

| Field | Type | Description |
| :---- | :--- | :---------- |
| Hash | `string` | The inner hash function to use. See the supported [hash algorithms](#hash-algorithms). |
| Length | `uint64` | The length (in bits) of the key to generate. If unspecified, the recommended length will be used, which is the size of the associated hash function's block size. |

###### ImportParams

As specified in [§29.3](https://www.w3.org/TR/WebCryptoAPI/#hmac-importparams)

| Field | Type | Description |
| :---- | :--- | :---------- |
| Hash | `string` | The inner hash function to use. See the supported [hash algorithms](#hash-algorithms). |
| Length | `uint64` | The length (in bits) of the key. |

#### Examples

```go
package main

import (
	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/hmac"
)

func main() {
	// generate a new key
	key, err := webcrypto.Subtle().GenerateKey(
		&webcrypto.Algorithm{
			Name: "HMAC",
			Params: &hmac.KeyGenParams{
				Hash: "SHA-256",
			},
		}, true, []webcrypto.KeyUsage{
			webcrypto.Sign,
			webcrypto.Verify,
	})

	if err != nil {
		panic(err)
	}

	// the generated key returns a webcrypto.CryptoKey
	cryptokey := key.(webcrypto.CryptoKey)

	// sign some data - no params required.
	sig, err := webcrypto.Subtle().Sign(&webcrypto.Algorithm{
		Name: "HMAC",
	}, cryptokey, []byte("test"))

	if err != nil {
		panic(err)
	}

	// verify the signature
	ok, err := webcrypto.Subtle().Verify(&webcrypto.Algorithm{
		Name: "HMAC",
	}, cryptokey, sig, []byte("test"))

	if err != nil {
		panic(err)
	}

	// export the key as *webcrypto.JsonWebKey
	out, err := webcrypto.Subtle().ExportKey(webcrypto.Jwk, cryptoKey)
	if err != nil {
		panic(err)
	}

	jwk := out.(*webcrypto.JsonWebKey)
	// do something with jwk

	// export the key as raw bytes
	out, err = webcrypto.Subtle().ExportKey(webcrypto.Raw, cryptoKey)
	if err != nil {
		panic(err)
	}

	raw := out.([]byte)
	// do something with raw bytes

	// import a key from a jwk
	in, err := webcrypto.Subtle().ImportKey(
		webcrypto.Jwk, 
		jwk, 
		&webcrypto.Algorithm{
			Name: "HMAC",
			Params: &hmac.ImportParams{
				Hash: "SHA-256",
			},
		}, 
		true, 
		[]webcrypto.KeyUsage{
			webcrypto.Sign,
			webcrypto.Verify,
		})
	
	if err != nil {
		panic(err)
	}

	// import a key from raw bytes
	in, err = webcrypto.Subtle().ImportKey(
		webcrypto.Raw, 
		raw, 
		&webcrypto.Algorithm{
			Name: "HMAC",
			Params: &hmac.ImportParams{
				Hash: "SHA-256",
			},
		}, 
		true, 
		[]webcrypto.KeyUsage{
			webcrypto.Sign,
			webcrypto.Verify,
		})
	
	if err != nil {
		panic(err)
	}

	// do something with your imported keys
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

## Apendix

### Hash Algorithms

Unless otherwise specified by a particular algorithm, the supported hash algorithms are 
- `SHA-1`
- `SHA-256`
- `SHA-384`
- `SHA-512`