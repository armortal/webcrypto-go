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

// Package ecdsa implements ECDSA operations as specified in the algorithms at
// §23 https://www.w3.org/TR/WebCryptoAPI/#ecdsa
package ecdsa

import (
	"errors"
	"fmt"
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
		k, err := new(SubtleCrypto).GenerateKey(&Algorithm{
			KeyGenParams: &KeyGenParams{
				NamedCurve: curve,
			},
		}, extractable, usages...)
		if err != nil {
			t.Error(err)
		}
		ckp := k.(webcrypto.CryptoKeyPair)

		if err := validate(ckp.PublicKey(), webcrypto.Public, curve, extractable, []webcrypto.KeyUsage{webcrypto.Verify}); err != nil {
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

		if err := generateAndValidate(P256, true, []webcrypto.KeyUsage{webcrypto.Verify}); err != nil {
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
		if err := generateAndValidate(P384, true, []webcrypto.KeyUsage{webcrypto.Verify}); err != nil {
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
		if err := generateAndValidate(P521, true, []webcrypto.KeyUsage{webcrypto.Verify}); err != nil {
			t.Error(err)
		}
	})
}
