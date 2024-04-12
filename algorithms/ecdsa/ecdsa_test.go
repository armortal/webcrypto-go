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

// Package ecdsa implements ECDSA operations as described in the specifications at
// §23 (https://www.w3.org/TR/WebCryptoAPI/#ecdsa).
package ecdsa

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/armortal/webcrypto-go"
)

func Test_GenerateKey(t *testing.T) {
	validate := func(key webcrypto.CryptoKey, keyType webcrypto.KeyType, curve string, extractable bool, usages []webcrypto.KeyUsage) error {
		if key.Type() != keyType {
			return errors.New("invalid key type")
		}

		alg, ok := key.Algorithm().(*KeyAlgorithm)
		if !ok {
			return errors.New("Algorithm() must be *KeyAlgorithm")
		}
		if alg.NamedCurve() != curve {
			return errors.New("invalid named curve")
		}
		if key.Extractable() != extractable {
			return errors.New("extractable mismatch")
		}

		if len(key.Usages()) != len(usages) {
			return errors.New("invalid usages")
		}

	usages:
		for _, exp := range usages {
			for _, act := range key.Usages() {
				if exp == act {
					continue usages
				}
			}
			return fmt.Errorf("usage '%s' not in crypto key", exp)
		}
		return nil
	}

	generateAndValidate := func(curve string, extractable bool, usages []webcrypto.KeyUsage) error {
		k, err := subtle.GenerateKey(&webcrypto.Algorithm{
			Name: "ECDSA",
			Params: &KeyGenParams{
				NamedCurve: curve,
			},
		}, extractable, usages...)
		if err != nil {
			t.Error(err)
		}
		ckp := k.(webcrypto.CryptoKeyPair)

		if err := validate(ckp.PublicKey(), webcrypto.Public, curve, true, []webcrypto.KeyUsage{webcrypto.Verify}); err != nil {
			return err
		}

		if err := validate(ckp.PrivateKey(), webcrypto.Private, curve, extractable, []webcrypto.KeyUsage{webcrypto.Sign}); err != nil {
			return err
		}

		return nil
	}

	t.Run("generate a valid P-256 key", func(t *testing.T) {
		if err := generateAndValidate(P256, true, []webcrypto.KeyUsage{webcrypto.Sign}); err != nil {
			t.Error(err)
		}

		if err := generateAndValidate(P256, true, []webcrypto.KeyUsage{webcrypto.Sign, webcrypto.Verify}); err != nil {
			t.Error(err)
		}

		if err := generateAndValidate(P256, false, []webcrypto.KeyUsage{webcrypto.Verify}); err != nil {
			t.Error(err)
		}
	})

	t.Run("generate a valid P-384 key", func(t *testing.T) {
		if err := generateAndValidate(P384, true, []webcrypto.KeyUsage{webcrypto.Sign}); err != nil {
			t.Error(err)
		}
		if err := generateAndValidate(P384, true, []webcrypto.KeyUsage{webcrypto.Sign, webcrypto.Verify}); err != nil {
			t.Error(err)
		}
		if err := generateAndValidate(P384, false, []webcrypto.KeyUsage{webcrypto.Verify}); err != nil {
			t.Error(err)
		}
	})

	t.Run("generate a valid P-521 key", func(t *testing.T) {
		if err := generateAndValidate(P521, true, []webcrypto.KeyUsage{webcrypto.Sign}); err != nil {
			t.Error(err)
		}
		if err := generateAndValidate(P521, true, []webcrypto.KeyUsage{webcrypto.Sign, webcrypto.Verify}); err != nil {
			t.Error(err)
		}
		if err := generateAndValidate(P521, false, []webcrypto.KeyUsage{webcrypto.Verify}); err != nil {
			t.Error(err)
		}
	})
}

func Test_SignAndVerify(t *testing.T) {
	k, err := subtle.GenerateKey(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &KeyGenParams{
			NamedCurve: P256,
		},
	}, false, webcrypto.Sign)
	if err != nil {
		t.Error(err)
	}
	ckp := k.(webcrypto.CryptoKeyPair)

	signAndVerify(t, ckp.PrivateKey(), ckp.PublicKey(), "SHA-1", []byte("Hello, world!"))
	signAndVerify(t, ckp.PrivateKey(), ckp.PublicKey(), "SHA-256", []byte("Hello, world!"))
	signAndVerify(t, ckp.PrivateKey(), ckp.PublicKey(), "SHA-384", []byte("Hello, world!"))
	signAndVerify(t, ckp.PrivateKey(), ckp.PublicKey(), "SHA-512", []byte("Hello, world!"))
}

func signAndVerify(t *testing.T, priv webcrypto.CryptoKey, pub webcrypto.CryptoKey, hashFn string, data []byte) {
	b, err := subtle.Sign(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &Params{
			Hash: hashFn,
		},
	}, priv, data)
	if err != nil {
		t.Error(err)
	}

	ok, err := subtle.Verify(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &Params{
			Hash: hashFn,
		},
	}, pub, b, data)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("sig mismatch")
	}

	// test inputting and public into sign() and private key into verify()
	_, err = subtle.Sign(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &Params{
			Hash: hashFn,
		},
	}, pub, data)
	if err == nil {
		t.Error("public key should not be allowed in sign()")
	}

	ok, err = subtle.Verify(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &Params{
			Hash: hashFn,
		},
	}, priv, b, data)
	if err == nil {
		t.Error("private key should not be allowed in verify()")
	}

	if ok {
		t.Error("false should have been returned")
	}
}

func Test_testData(t *testing.T) {
	b, err := os.ReadFile("testdata/data.json")
	if err != nil {
		t.Error(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Error(err)
	}

	b, err = json.Marshal(m["publicKey"])
	if err != nil {
		t.Error(err)
	}

	var jwk webcrypto.JsonWebKey
	if err := json.Unmarshal(b, &jwk); err != nil {
		t.Error(err)
	}

	k, err := subtle.ImportKey(webcrypto.Jwk, &jwk, &webcrypto.Algorithm{Name: "ECDSA", Params: &KeyImportParams{NamedCurve: P256}}, true, webcrypto.Verify)
	if err != nil {
		t.Error(err)
	}

	sig, err := base64.StdEncoding.DecodeString(m["signature"].(string))
	if err != nil {
		t.Error(err)
	}

	ok, err := subtle.Verify(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &Params{
			Hash: m["hash"].(string),
		},
	}, k, sig, []byte("test"))
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("verify failed")
	}
}

func Test_ExportAndImportJsonWebKey(t *testing.T) {
	k, err := subtle.GenerateKey(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &KeyGenParams{
			NamedCurve: P256,
		},
	}, true, webcrypto.Sign)
	if err != nil {
		t.Error(err)
	}

	// lets sign a message that we'll verify after importing
	data := []byte("Hello, world!")
	sig, err := subtle.Sign(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &Params{
			Hash: "SHA-256",
		},
	}, k.(webcrypto.CryptoKeyPair).PrivateKey(), data)
	if err != nil {
		t.Error(err)
	}

	// export the private key and verify the jwk
	priv, err := subtle.ExportKey(webcrypto.Jwk, k.(webcrypto.CryptoKeyPair).PrivateKey())
	if err != nil {
		t.Error(err)
	}

	jwk := priv.(*webcrypto.JsonWebKey)
	if jwk.Crv != "P-256" {
		t.Error("invalid crv")
	}
	if jwk.Kty != "EC" {
		t.Error("invalid kty")
	}
	if jwk.Y == "" || jwk.X == "" || jwk.D == "" {
		t.Error("invalid y|x|d")
	}
	if len(jwk.KeyOps) != 1 || jwk.KeyOps[0] != webcrypto.Sign {
		t.Error("invalid key_ops")
	}
	if !jwk.Ext {
		t.Error("invalid ext")
	}

	// export the public key and verify the jwk
	pub, err := subtle.ExportKey(webcrypto.Jwk, k.(webcrypto.CryptoKeyPair).PublicKey())
	if err != nil {
		t.Error(err)
	}

	jwk = pub.(*webcrypto.JsonWebKey)
	if jwk.Crv != "P-256" {
		t.Error("invalid crv")
	}
	if jwk.Kty != "EC" {
		t.Error("invalid kty")
	}
	if jwk.Y == "" || jwk.X == "" {
		t.Error("invalid x|y")
	}
	if len(jwk.KeyOps) != 1 || jwk.KeyOps[0] != webcrypto.Verify {
		t.Error("invalid key_ops")
	}
	if !jwk.Ext {
		t.Error("invalid ext")
	}

	// import the key
	imp, err := subtle.ImportKey(webcrypto.Jwk, jwk, &webcrypto.Algorithm{Name: "ECDSA", Params: &KeyImportParams{NamedCurve: P256}}, true, webcrypto.Verify)
	if err != nil {
		t.Error(err)
	}

	ok, err := subtle.Verify(&webcrypto.Algorithm{
		Name: "ECDSA",
		Params: &Params{
			Hash: "SHA-256",
		},
	}, imp, sig, data)
	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.Error("verify failed")
	}

	// export the key and verify the jwk
	_, err = subtle.ExportKey(webcrypto.PKCS8, k.(webcrypto.CryptoKeyPair).PrivateKey())
	if err != nil {
		t.Error(err)
	}
}
