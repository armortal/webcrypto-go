# webcrypto-go [![test](https://github.com/armortal/webcrypto-go/actions/workflows/test.yaml/badge.svg)](https://github.com/armortal/webcrypto-go/actions/workflows/test.yaml)

An implementation of the W3C Web Cryptography API specification (https://www.w3.org/TR/WebCryptoAPI/) for Go using Go's standard `crypto` library.

> [!IMPORTANT]  
> Whilst we try to ensure that we don't commit breaking changes until we release our first major version, there
> may be times where decisions made during early development no longer make sense and therefore require
> breaking changes. Please be mindful of this when updating your version of this library until we hit `v1.0.0`.

## Contents

- [Background](#background)
- [Implementation status](#implementation-status)
- [Getting started](#getting-started)
- [Algorithms](#algorithms)
	- [ECDSA](#ecdsa)
		- [Parameter Definitions](#parameter-definitions)
		- [Examples](#examples)
	- [HMAC](#hmac)
		- [Parameter Definitions](#parameter-definitions-1)
		- [Examples](#examples-1)
	- [RSA-OAEP](#rsa-oaep)
		- [Parameter Definitions](#parameter-definitions-2)
		- [Examples](#examples-2)
	- [RSASSA-PKCS1-v1_5](#rsassa-pkcs1-v1_5)
		- [Parameter Definitions](#parameter-definitions-3)
	- [SHA](#sha)
		- [Parameter Definitions](#parameter-definitions-4)
		- [Examples](#examples-3)
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

The **ECDSA** algorithm is the implementation of operations described in [§23](https://www.w3.org/TR/WebCryptoAPI/#ecdsa) of the W3C specification. 

`import "github.com/armortal/webcrypto-go/algorithms/ecdsa"`

#### Parameter Definitions

Below are the parameters that supported ECDSA operations will take according to 
[§23.2](https://www.w3.org/TR/WebCryptoAPI/#ecdsa-registration).

##### Params

As specified in [§23.3](https://www.w3.org/TR/WebCryptoAPI/#EcdsaParams-dictionary)

| Field | Type | Description |
| :---- | :--- | :---------- |
| Hash | `string` | The hash algorithm to use. See the supported [hash algorithms](#parameter-definitions-4) |

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
	"fmt"

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

	// key returned is a webcrypto.CryptoKeyPair that contains two *ecdsa.CryptoKey
	cryptoKeyPair := key.(webcrypto.CryptoKeyPair)

	// sign some data with the private key
	sig, err := webcrypto.Subtle().Sign(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &ecdsa.Params{
			Hash: "SHA-256",
		},
	}, cryptoKeyPair.PrivateKey(), []byte("test"))
	if err != nil {
		panic(err)
	}

	// verify the signature with the public key
	ok, err := webcrypto.Subtle().Verify(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &ecdsa.Params{
			Hash: "SHA-256",
		},
	}, cryptoKeyPair.PublicKey(), sig, []byte("test"))
	if err != nil {
		panic(err)
	}

	if !ok {
		panic("signature didn't verify")
	}

	// export the public/private key as webcrypto.JsonWebKey
	out, err := webcrypto.Subtle().ExportKey(webcrypto.Jwk, cryptoKeyPair.PrivateKey())
	if err != nil {
		panic(err)
	}

	// do something with jwk
	jwk := out.(*webcrypto.JsonWebKey)

	// export the key as PKCS8
	out, err = webcrypto.Subtle().ExportKey(webcrypto.PKCS8, cryptoKeyPair.PrivateKey())
	if err != nil {
		panic(err)
	}

	// do something with the pkcs8 key
	pkcs8 := out.([]byte)

	// import a public/private key from a jwk
	in, err := webcrypto.Subtle().ImportKey(webcrypto.Jwk, jwk, &webcrypto.Algorithm{
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

	// import a public/private key from PKCS8
	in, err = webcrypto.Subtle().ImportKey(webcrypto.PKCS8, pkcs8, &webcrypto.Algorithm{
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
	fmt.Println(in.Type())
}
```

### HMAC

The **HMAC** algorithm is the implementation of operations described in [§29](https://www.w3.org/TR/WebCryptoAPI/#hmac) of the W3C specification. 

`import "github.com/armortal/webcrypto-go/algorithms/hmac"`

#### Parameter Definitions

Below are the parameters that supported HMAC operations will take according to 
[§29.2](https://www.w3.org/TR/WebCryptoAPI/#hmac-registration).

##### KeyGenParams

As specified in [§29.5](https://www.w3.org/TR/WebCryptoAPI/#hmac-keygen-params)

| Field | Type | Description |
| :---- | :--- | :---------- |
| Hash | `string` | The inner hash function to use. See the supported [hash algorithms](#parameter-definitions-4). |
| Length | `uint64` | The length (in bits) of the key to generate. If unspecified, the recommended length will be used, which is the size of the associated hash function's block size. |

##### ImportParams

As specified in [§29.3](https://www.w3.org/TR/WebCryptoAPI/#hmac-importparams)

| Field | Type | Description |
| :---- | :--- | :---------- |
| Hash | `string` | The inner hash function to use. See the supported [hash algorithms](#parameter-definitions-4). |
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

`import "github.com/armortal/webcrypto-go/algorithms/rsa"`

#### Parameter Definitions

Below are the parameters that supported RSA-OAEP operations will take according to 
[§22.2](https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-registration).

#### OaepParams

As specified in [§22.3](https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-params)

| Field | Type | Description |
| :---- | :--- | :---------- |
| Label | `string` | The optional label/application data to associate with the message. |

#### Examples

```go
package main

import (
	"fmt"
	"math/big"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/rsa"
)

func main() {
	// generate a new key
	key, err := webcrypto.Subtle().GenerateKey(
		&webcrypto.Algorithm{
			Name: "RSA-OAEP",
			Params: &rsa.HashedKeyGenParams{
				KeyGenParams: rsa.KeyGenParams{
					ModulusLength:  2048,
					PublicExponent: big.NewInt(65537),
				},
				Hash: "SHA-256",
			},
		}, true, []webcrypto.KeyUsage{webcrypto.Decrypt, webcrypto.Encrypt})

	if err != nil {
		panic(err)
	}

	cryptoKeyPair := key.(webcrypto.CryptoKeyPair)

	// encrypt some data with an optional label
	encrypted, err := webcrypto.Subtle().Encrypt(&webcrypto.Algorithm{
		Name: "RSA-OAEP",
		Params: &rsa.OaepParams{
			Label: []byte("optional"),
		},
	}, cryptoKeyPair.PublicKey(), []byte("test"))

	if err != nil {
		panic(err)
	}

	// decrypt the data
	decrypted, err := webcrypto.Subtle().Decrypt(&webcrypto.Algorithm{
		Name: "RSA-OAEP",
		Params: &rsa.OaepParams{
			Label: []byte("optional"),
		},
	}, cryptoKeyPair.PrivateKey(), encrypted)

	if err != nil {
		panic(err)
	}

	// do something with decrypted data
	fmt.Println(string(decrypted))

	// export the private/public key as jwk
	out, err := webcrypto.Subtle().ExportKey(webcrypto.Jwk, cryptoKeyPair.PrivateKey())
	if err != nil {
		panic(err)
	}

	// do something with jwk
	jwk := out.(*webcrypto.JsonWebKey)

	// import a key from jwk
	in, err := webcrypto.Subtle().ImportKey(webcrypto.Jwk, jwk, &webcrypto.Algorithm{
		Name: "RSA-OAEP",
		Params: &rsa.HashedImportParams{
			Hash: "SHA-256",
		},
	}, true, []webcrypto.KeyUsage{webcrypto.Decrypt})

	if err != nil {
		panic(err)
	}

	// do something with the imported key
	fmt.Println(in.Type())
}
```

### RSASSA-PKCS1-v1_5

This algorithm is currently not supported. However, parameter definitions for those used in [RSA-OAEP](#rsa-oaep) operations 
come from those defined in this algorithm.

#### Parameter Definitions

Below are the parameters that supported RSASSA-PKCS1-v1_5 operations will take according to 
[§20.2](https://www.w3.org/TR/WebCryptoAPI/#rsassa-pkcs1-registration).

##### KeyGenParams

As specified in [§20.3](https://www.w3.org/TR/WebCryptoAPI/#RsaKeyGenParams-dictionary)

| Field | Type | Description |
| :---- | :--- | :---------- |
| ModulusLength | `uint64` | The length, in bits, of the RSA modulus. |
| PublicExponent | `*big.Int` | The RSA public exponent. |

##### HashedKeyGenParams

As specified in [§20.4](https://www.w3.org/TR/WebCryptoAPI/#RsaHashedKeyGenParams-dictionary)

| Field | Type | Description |
| :---- | :--- | :---------- |
| Hash | `string` | The [hash algorithm](#parameter-definitions-4) to use. |
| ModulusLength | `uint64` | The length, in bits, of the RSA modulus. |
| PublicExponent | `*big.Int` | The RSA public exponent. |

##### HashedImportParams

As specified in [§20.7](https://www.w3.org/TR/WebCryptoAPI/#RsaHashedImportParams-dictionary)

| Field | Type | Description |
| :---- | :--- | :---------- |
| Hash | `string` | The [hash algorithm](#parameter-definitions-4) to use. |


### SHA

The **SHA** algorithm is the implementation of operations described in [§30](https://www.w3.org/TR/WebCryptoAPI/#sha) of the W3C specification.

`import "github.com/armortal/webcrypto-go/algorithms/sha"`

#### Parameter Definitions

Below are the recognized algorithm names for supported SHA operations according to 
[§30.2](https://www.w3.org/TR/WebCryptoAPI/#sha-registration).

- `SHA-1`
- `SHA-256`
- `SHA-384`
- `SHA-512`

There are no parameter definitions, however we use [Params](#params-1) below for importing purposes.

##### Params

This is an empty struct that we use to register SHA algorithms without using a blank import. If you don't
use this as in `webcrypto.Algorithm.Params` to the `Digest()` call, you can import the algorithm using
a blank import like below:

`import _ "github.com/armortal/webcrypto-go/algorithms/sha"`

#### Examples

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/sha"
)

func main() {
	// digest something
	hash, err := webcrypto.Subtle().Digest(
		&webcrypto.Algorithm{
			Name:   "SHA-256",
			Params: &sha.Params{}, // we use *sha.Params so we can register the algorithm without using a blank import
		}, []byte("test"))

	if err != nil {
		panic(err)
	}

	// do something with hash
	fmt.Println(hex.EncodeToString(hash))
}

```

## Contributing

If you have found a bug or would like to see new features, please create a new issue in this repository. If there is an issue that poses a security risk, please refrain from posting the issue publicly and contact [support@armortal.com](mailto://support@armortal.com) instead.