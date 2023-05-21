// Copyright 2023 ARMORTAL TECHNOLOGIES PTY LTD

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.package rsa

package rsa

import (
	"math/big"
	"testing"

	"github.com/armortal/webcrypto-go"
)

func TestOaep_GenerateKey(t *testing.T) {
	alg := &algorithm{}

	t.Run("generate successful key pair", func(t *testing.T) {
		key, err := alg.GenerateKey(&HashedKeyGenParams{
			KeyGenParams: KeyGenParams{
				Name:          "RSA-OAEP",
				ModulusLength: 2048,
				Exponent:      *big.NewInt(65537),
			},
			Hash: "SHA-256",
		}, true, webcrypto.Decrypt, webcrypto.Encrypt)
		if err != nil {
			t.Fatal(err)
		}

		ckp, ok := key.(webcrypto.CryptoKeyPair)
		if !ok {
			t.Fatal("key should have been *CryptoKeyPair")
		}

		pub := ckp.PublicKey()
		if pub.Type() != "public" {
			t.Fatal("public key type is not 'public'")
		}

		if !pub.Extractable() {
			t.Fatal("public key ext should be true")
		}

		if len(pub.Usages()) != 1 {
			t.Fatal("invalid usages")
		}

		if pub.Usages()[0] != webcrypto.Encrypt {
			t.Fatal("public key usage should have been encrypt")
		}

		priv := ckp.PrivateKey()
		if priv.Type() != "private" {
			t.Fatal("private key type is not 'private'")
		}

		if !priv.Extractable() {
			t.Fatal("private key ext should be true")
		}

		if len(priv.Usages()) != 1 {
			t.Fatal("invalid usages")
		}

		if priv.Usages()[0] != webcrypto.Decrypt {
			t.Fatal("private key usage should have been decrypt")
		}

	})

	t.Run("invalid exponent", func(t *testing.T) {
		_, err := alg.GenerateKey(&HashedKeyGenParams{
			KeyGenParams: KeyGenParams{
				Name:          "RSA-OAEP",
				ModulusLength: 2048,
				Exponent:      *big.NewInt(65536),
			},
			Hash: "SHA-256",
		}, true)
		if err == nil {
			t.Fatal("error should have been returned")
		}
	})

	t.Run("invalid usages", func(t *testing.T) {
		_, err := alg.GenerateKey(&HashedKeyGenParams{
			KeyGenParams: KeyGenParams{
				Name:          "RSA-OAEP",
				ModulusLength: 2048,
				Exponent:      *big.NewInt(65537),
			},
			Hash: "SHA-256",
		}, true)
		if err == nil {
			t.Fatal("error should have been returned")
		}
	})

	t.Run("invalid algorithm name", func(t *testing.T) {
		_, err := alg.GenerateKey(&HashedKeyGenParams{
			KeyGenParams: KeyGenParams{
				Name:          "RSA-OAEP-invalid-name",
				ModulusLength: 2048,
				Exponent:      *big.NewInt(65537),
			},
			Hash: "SHA-256",
		}, true)
		if err == nil {
			t.Fatal("error should have been returned")
		}
	})

}
