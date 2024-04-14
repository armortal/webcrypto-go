// Copyright 2023-2024 ARMORTAL TECHNOLOGIES PTY LTD

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.package rsa

// Package rsa implements RSA operations;
// RSA-OAEP as specified in §30 (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep).
package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/armortal/webcrypto-go"
)

func TestEncryptDecrypt(t *testing.T) {
	key, err := oaepSubtle.GenerateKey(&webcrypto.Algorithm{
		Name: "RSA-OAEP",
		Params: &HashedKeyGenParams{
			KeyGenParams: KeyGenParams{
				ModulusLength:  2048,
				PublicExponent: *big.NewInt(65537),
			},
			Hash: "SHA-256",
		},
	}, true, []webcrypto.KeyUsage{webcrypto.Decrypt, webcrypto.Encrypt})
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("helloworld")
	b, err := oaepSubtle.Encrypt(&webcrypto.Algorithm{
		Name:   "RSA-OAEP",
		Params: &OaepParams{},
	}, key.(webcrypto.CryptoKeyPair).PublicKey(), msg)
	if err != nil {
		t.Fatal(err)
	}

	v, err := oaepSubtle.Decrypt(&webcrypto.Algorithm{
		Name:   "RSA-OAEP",
		Params: &OaepParams{},
	}, key.(webcrypto.CryptoKeyPair).PrivateKey(), b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, v) {
		t.Fatal("msg mismatch")
	}
}

func TestOaep_ExportKey(t *testing.T) {
	key, err := oaepSubtle.GenerateKey(&webcrypto.Algorithm{
		Name: "RSA-OAEP",
		Params: &HashedKeyGenParams{
			KeyGenParams: KeyGenParams{
				ModulusLength:  2048,
				PublicExponent: *big.NewInt(65537),
			},
			Hash: "SHA-256",
		},
	}, true, []webcrypto.KeyUsage{webcrypto.Decrypt, webcrypto.Encrypt})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("export jwk", func(t *testing.T) {
		pk := key.(webcrypto.CryptoKeyPair).PrivateKey()
		out, err := oaepSubtle.ExportKey(webcrypto.Jwk, pk)
		if err != nil {
			t.Fatal(err)
		}

		if jwk, ok := out.(*webcrypto.JsonWebKey); ok {
			if jwk.Kty != "RSA" {
				t.Fatal("invalid kty")
			}
			if !jwk.Ext {
				t.Fatal("invalid ext")
			}
			if len(jwk.KeyOps) != 1 {
				t.Fatal("invalid keyops length")
			}

			if jwk.KeyOps[0] != webcrypto.Decrypt {
				t.Fatal("invalid key op")
			}

			if jwk.Alg != "RSA-OAEP-256" {
				t.Fatal("invalid alg")
			}

			encode := func(in []byte) string {
				return base64.RawURLEncoding.EncodeToString(in)
			}

			rsa := pk.(*CryptoKey).priv
			if jwk.N != encode(rsa.N.Bytes()) {
				t.Fatal("n mismatch")
			}

			if jwk.E != encode(big.NewInt(int64(rsa.E)).Bytes()) {
				t.Fatal("e mismatch")
			}

			if jwk.D != encode(rsa.D.Bytes()) {
				t.Fatal("d mismatch")
			}

			if jwk.Dp != encode(rsa.Precomputed.Dp.Bytes()) {
				t.Fatal("dp mismatch")
			}

			if jwk.Dq != encode(rsa.Precomputed.Dq.Bytes()) {
				t.Fatal("dq mismatch")
			}

			if jwk.Qi != encode(rsa.Precomputed.Qinv.Bytes()) {
				t.Fatal("qi mismatch")
			}
		} else {
			t.Fatal("exported key should have been *webcrypto.JsonWebKey")
		}
	})

	t.Run("export PKCS8", func(t *testing.T) {
		out, err := oaepSubtle.ExportKey(webcrypto.PKCS8, key.(webcrypto.CryptoKeyPair).PrivateKey())
		if err != nil {
			t.Fatal(err)
		}
		if b, ok := out.([]byte); ok {
			k, err := x509.ParsePKCS8PrivateKey(b)
			if err != nil {
				t.Fatal(err)
			}

			if _, ok := k.(*rsa.PrivateKey); !ok {
				t.Fatal("key should have been *rsa.PrivateKey")
			}
		} else {
			t.Fatal("exported key should have been []byte")
		}
	})
}

func TestOaep_GenerateKey(t *testing.T) {
	t.Run("generate successful key pair", func(t *testing.T) {
		key, err := oaepSubtle.GenerateKey(&webcrypto.Algorithm{
			Name: "RSA-OAEP",
			Params: &HashedKeyGenParams{
				KeyGenParams: KeyGenParams{
					ModulusLength:  2048,
					PublicExponent: *big.NewInt(65537),
				},
				Hash: "SHA-256",
			},
		}, true, []webcrypto.KeyUsage{webcrypto.Decrypt, webcrypto.Encrypt})
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
		_, err := oaepSubtle.GenerateKey(&webcrypto.Algorithm{
			Name: "RSA-OAEP",
			Params: &HashedKeyGenParams{
				KeyGenParams: KeyGenParams{
					ModulusLength:  2048,
					PublicExponent: *big.NewInt(65536),
				},
				Hash: "SHA-256",
			},
		}, true, nil)
		if err == nil {
			t.Fatal("error should have been returned")
		}
	})

	t.Run("invalid usages", func(t *testing.T) {
		_, err := oaepSubtle.GenerateKey(&webcrypto.Algorithm{
			Name: "RSA-OAEP",
			Params: &HashedKeyGenParams{
				KeyGenParams: KeyGenParams{
					ModulusLength:  2048,
					PublicExponent: *big.NewInt(65537),
				},
				Hash: "SHA-256",
			},
		}, true, nil)
		if err == nil {
			t.Fatal("error should have been returned")
		}
	})

	t.Run("invalid algorithm name", func(t *testing.T) {
		_, err := oaepSubtle.GenerateKey(&webcrypto.Algorithm{
			Name: "RSA-OAEP-invalid-name",
			Params: &HashedKeyGenParams{
				KeyGenParams: KeyGenParams{
					ModulusLength:  2048,
					PublicExponent: *big.NewInt(65537),
				},
				Hash: "SHA-256",
			},
		}, true, nil)
		if err == nil {
			t.Fatal("error should have been returned")
		}
	})

}

func TestOaep_ImportKey(t *testing.T) {
	key, err := oaepSubtle.GenerateKey(&webcrypto.Algorithm{
		Name: "RSA-OAEP",
		Params: &HashedKeyGenParams{
			KeyGenParams: KeyGenParams{
				ModulusLength:  2048,
				PublicExponent: *big.NewInt(65537),
			},
			Hash: "SHA-256",
		},
	}, true, []webcrypto.KeyUsage{webcrypto.Decrypt, webcrypto.Encrypt})
	if err != nil {
		t.Fatal(err)
	}

	data, err := oaepSubtle.ExportKey(webcrypto.Jwk, key.(webcrypto.CryptoKeyPair).PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("import jwk", func(t *testing.T) {
		in, err := oaepSubtle.ImportKey(webcrypto.Jwk, data, &webcrypto.Algorithm{
			Name: "RSA-OAEP",
			Params: &HashedImportParams{
				Hash: "SHA-256",
			},
		}, true, []webcrypto.KeyUsage{webcrypto.Decrypt})
		if err != nil {
			t.Fatal(err)
		}

		if in.Algorithm().Name() != "RSA-OAEP" {
			t.Fatal()
		}

		if in.Extractable() != true {
			t.Fatal()
		}

		if in.Type() != webcrypto.Private {
			t.Fatal()
		}

	})
}
