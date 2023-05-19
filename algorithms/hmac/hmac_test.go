// Copyright 2023 ARMORTAL TECHNOLOGIES PTY LTD

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hmac

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/sha256"
)

const (
	input             string = "helloworld"
	inputHexSignature string = "771cd8fbd3ae11336582fd5d4fff15e1e7c7cadee407b78fcc11284c8e811b12"
	rawHexKey                = "917d6047d5fdfc4309308d45d44facd50cafd88317e0153aa3af3555eb14c66a0ce19f771a61c1db6490ff2eca686806ba64b9b56bc42e743b6f2422c38eebc9"
)

func TestGenerateKey(t *testing.T) {
	alg := New(WithHash(sha256.New()))

	usages := []webcrypto.KeyUsage{
		webcrypto.Sign, webcrypto.Verify,
	}

	res, err := alg.GenerateKey(alg, true, usages...)
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

	_, err = generateKey(alg, true)
	if err == nil {
		t.Fatal("error should have been returned for invalid usages")
	}
}

func TestExportKey(t *testing.T) {
	alg := New(WithHash(sha256.New()))
	raw, err := hex.DecodeString(rawHexKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := alg.ImportKey(webcrypto.Raw, raw, alg, true, usages...)
	if err != nil {
		t.Fatal(err)
	}

	exp, err := alg.ExportKey(webcrypto.Raw, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(raw, exp.([]byte)) {
		t.Fatal("key mismatch")
	}
}

func TestImportKey(t *testing.T) {
	alg := New(WithHash(sha256.New()))

	raw, err := hex.DecodeString(rawHexKey)
	if err != nil {
		t.Fatal(err)
	}

	key, err := alg.ImportKey(webcrypto.Raw, raw, alg, true, usages...)
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

func TestSign(t *testing.T) {
	alg := New(WithHash(sha256.New()))
	raw, err := hex.DecodeString(rawHexKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := alg.ImportKey(webcrypto.Raw, raw, alg, true, usages...)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := alg.Sign(alg, key, bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatal(err)
	}

	sigDecoded, err := hex.DecodeString(inputHexSignature)
	if !bytes.Equal(sig, sigDecoded) {
		t.Fatal(err)
	}
}

func TestVerify(t *testing.T) {
	alg := New(WithHash(sha256.New()))
	raw, err := hex.DecodeString(rawHexKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := importKeyFromRaw(raw, alg, true, usages...)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(inputHexSignature)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := alg.Verify(alg, key, sig, []byte(input))
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("signature mismatch")
	}
}
