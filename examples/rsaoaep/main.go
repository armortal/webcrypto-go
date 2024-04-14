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
					PublicExponent: *big.NewInt(65537),
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
