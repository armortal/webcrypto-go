// Copyright 2023-2025 ARMORTAL TECHNOLOGIES PTY LTD

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package hmac implements HMAC operations as described in the specifications at
// §29 (https://www.w3.org/TR/WebCryptoAPI/#hmac).
package hmac

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/armortal/webcrypto-go"
)

const (
	input             string = "helloworld"
	inputHexSignature string = "771cd8fbd3ae11336582fd5d4fff15e1e7c7cadee407b78fcc11284c8e811b12"
	rawHexKey                = "917d6047d5fdfc4309308d45d44facd50cafd88317e0153aa3af3555eb14c66a0ce19f771a61c1db6490ff2eca686806ba64b9b56bc42e743b6f2422c38eebc9"
)

func TestGenerateKey(t *testing.T) {
	usages := []webcrypto.KeyUsage{
		webcrypto.Sign, webcrypto.Verify,
	}

	res, err := subtle.GenerateKey(&webcrypto.Algorithm{
		Name: "HMAC",
		Params: &KeyGenParams{
			Hash:   "SHA-256",
			Length: 512,
		},
	}, true, usages)
	if err != nil {
		t.Fatal(err)
	}

	key := res.(webcrypto.CryptoKey)

	if key.Type() != "secret" {
		t.Fatal("key.Type must be 'secret'")
	}

	if !key.Extractable() {
		t.Fatal("key.Extractable should be true")
	}

	if !reflect.DeepEqual(key.Usages(), usages) {
		t.Fatal("usages mismatch")
	}

	if key.Algorithm().Name() != "HMAC" {
		t.Fatal("algorithm name mismatch")
	}

	// _, err = generateKey(alg, true)
	// if err == nil {
	// 	t.Fatal("error should have been returned for invalid usages")
	// }
}

func TestExportKey(t *testing.T) {
	raw, err := hex.DecodeString(rawHexKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := subtle.ImportKey(webcrypto.Raw, raw, &webcrypto.Algorithm{
		Name: "HMAC",
		Params: &ImportParams{
			Hash: "SHA-256",
		},
	}, true, usages)
	if err != nil {
		t.Fatal(err)
	}

	exp, err := subtle.ExportKey(webcrypto.Raw, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(raw, exp.([]byte)) {
		t.Fatal("key mismatch")
	}
}

func TestImportKey(t *testing.T) {
	raw, err := hex.DecodeString(rawHexKey)
	if err != nil {
		t.Fatal(err)
	}

	key, err := subtle.ImportKey(webcrypto.Raw, raw, &webcrypto.Algorithm{
		Name: "HMAC",
		Params: &ImportParams{
			Hash: "SHA-256",
		},
	}, true, usages)
	if err != nil {
		t.Fatal(err)
	}

	if key.Type() != "secret" {
		t.Fatal("key.Type must be 'secret'")
	}

	if !key.Extractable() {
		t.Fatal("key.Extractable should be true")
	}

	if !reflect.DeepEqual(key.Usages(), usages) {
		t.Fatal("usages mismatch")
	}

	if key.Algorithm().Name() != "HMAC" {
		t.Fatal("algorithm name mismatch")
	}

}

func Test_ImportKey_JsonWebKey(t *testing.T) {
	t.Run("import no use", func(t *testing.T) {
		k := `{"kty":"oct","key_ops":["sign","verify"],"alg":"HS256","ext":true,"k":"31G2ai1-ZfKsfQfNEQNga9H90J3q8pSHCBc9jcxM7IUzGwzofZJrNgCmE7lXOyR-_BxlA0NthOYT11NwRMOu1w"}`
		var jwk webcrypto.JsonWebKey
		if err := json.Unmarshal([]byte(k), &jwk); err != nil {
			t.Errorf("failed to unmarshal json: %s", err.Error())
		}

		_, err := subtle.ImportKey(webcrypto.Jwk, &jwk, &webcrypto.Algorithm{
			Name: "HMAC",
			Params: &ImportParams{
				Hash: "SHA-256",
			},
		}, true, []webcrypto.KeyUsage{webcrypto.Sign, webcrypto.Verify})
		if err != nil {
			t.Errorf("failed to import key: %s", err.Error())
		}
	})

	t.Run("import valid use", func(t *testing.T) {
		k := `{"kty":"oct","use":"sign","key_ops":["sign","verify"],"alg":"HS256","ext":true,"k":"31G2ai1-ZfKsfQfNEQNga9H90J3q8pSHCBc9jcxM7IUzGwzofZJrNgCmE7lXOyR-_BxlA0NthOYT11NwRMOu1w"}`
		var jwk webcrypto.JsonWebKey
		if err := json.Unmarshal([]byte(k), &jwk); err != nil {
			t.Errorf("failed to unmarshal json: %s", err.Error())
		}

		_, err := subtle.ImportKey(webcrypto.Jwk, &jwk, &webcrypto.Algorithm{
			Name: "HMAC",
			Params: &ImportParams{
				Hash: "SHA-256",
			},
		}, true, []webcrypto.KeyUsage{webcrypto.Sign, webcrypto.Verify})
		if err != nil {
			t.Errorf("failed to import key: %s", err.Error())
		}
	})

	t.Run("import invalid use", func(t *testing.T) {
		k := `{"kty":"oct","use":"enc","key_ops":["sign","verify"],"alg":"HS256","ext":true,"k":"31G2ai1-ZfKsfQfNEQNga9H90J3q8pSHCBc9jcxM7IUzGwzofZJrNgCmE7lXOyR-_BxlA0NthOYT11NwRMOu1w"}`
		var jwk webcrypto.JsonWebKey
		if err := json.Unmarshal([]byte(k), &jwk); err != nil {
			t.Errorf("failed to unmarshal json: %s", err.Error())
		}

		_, err := subtle.ImportKey(webcrypto.Jwk, &jwk, &webcrypto.Algorithm{
			Name: "HMAC",
			Params: &ImportParams{
				Hash: "SHA-256",
			},
		}, true, []webcrypto.KeyUsage{webcrypto.Sign, webcrypto.Verify})
		if err == nil {
			t.Error("importKey should have returned error")
		}
	})

	t.Run("import invalid key_ops", func(t *testing.T) {
		k := `{"kty":"oct","key_ops":["encrypt","verify"],"alg":"HS256","ext":true,"k":"31G2ai1-ZfKsfQfNEQNga9H90J3q8pSHCBc9jcxM7IUzGwzofZJrNgCmE7lXOyR-_BxlA0NthOYT11NwRMOu1w"}`
		var jwk webcrypto.JsonWebKey
		if err := json.Unmarshal([]byte(k), &jwk); err != nil {
			t.Errorf("failed to unmarshal json: %s", err.Error())
		}

		_, err := subtle.ImportKey(webcrypto.Jwk, &jwk, &webcrypto.Algorithm{
			Name: "HMAC",
			Params: &ImportParams{
				Hash: "SHA-256",
			},
		}, true, []webcrypto.KeyUsage{webcrypto.Sign, webcrypto.Verify})
		if err == nil {
			t.Error("importKey should have returned error")
		}
	})

	t.Run("import invalid key length", func(t *testing.T) {
		k := `{"kty":"oct","key_ops":["sign","verify"],"alg":"HS256","ext":true,"k":"VrmFU2huAL6phqi_vvGPvItpX2cJFy6rzjEQpjMqKA0"}`
		var jwk webcrypto.JsonWebKey
		if err := json.Unmarshal([]byte(k), &jwk); err != nil {
			t.Errorf("failed to unmarshal json: %s", err.Error())
		}

		_, err := subtle.ImportKey(webcrypto.Jwk, &jwk, &webcrypto.Algorithm{
			Name: "HMAC",
			Params: &ImportParams{
				Hash: "SHA-256",
			},
		}, true, []webcrypto.KeyUsage{webcrypto.Sign, webcrypto.Verify})
		if err == nil {
			t.Error("importKey should have returned error")
		}
	})
}

func TestSign(t *testing.T) {
	raw, err := hex.DecodeString(rawHexKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := subtle.ImportKey(webcrypto.Raw, raw, &webcrypto.Algorithm{
		Name: "HMAC",
		Params: &ImportParams{
			Hash: "SHA-256",
		},
	}, true, usages)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := subtle.Sign(&webcrypto.Algorithm{
		Name: "HMAC",
	}, key, []byte(input))
	if err != nil {
		t.Fatal(err)
	}

	sigDecoded, err := hex.DecodeString(inputHexSignature)
	if !bytes.Equal(sig, sigDecoded) {
		t.Fatal(err)
	}
}

func TestVerify(t *testing.T) {
	raw, err := hex.DecodeString(rawHexKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := subtle.ImportKey(webcrypto.Raw, raw, &webcrypto.Algorithm{
		Name: "HMAC",
		Params: &ImportParams{
			Hash: "SHA-256",
		},
	}, true, usages)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(inputHexSignature)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := subtle.Verify(&webcrypto.Algorithm{
		Name: "HMAC",
	}, key, sig, []byte(input))
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("signature mismatch")
	}
}
