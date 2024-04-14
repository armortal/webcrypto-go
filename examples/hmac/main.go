package main

import (
	"fmt"

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

	// the generated key returns a webcrypto.CryptoKey or
	// more specifically, a *hmac.CryptoKey
	cryptoKey := key.(webcrypto.CryptoKey)

	// sign some data - no params required.
	sig, err := webcrypto.Subtle().Sign(&webcrypto.Algorithm{
		Name: "HMAC",
	}, cryptoKey, []byte("test"))

	if err != nil {
		panic(err)
	}

	// verify the signature
	ok, err := webcrypto.Subtle().Verify(&webcrypto.Algorithm{
		Name: "HMAC",
	}, cryptoKey, sig, []byte("test"))

	if err != nil {
		panic(err)
	}

	if !ok {
		panic("signature didn't verify")
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
	fmt.Println(in.Type())
}
