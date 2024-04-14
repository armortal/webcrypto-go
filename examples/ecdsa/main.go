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
