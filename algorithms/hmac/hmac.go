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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/util"
)

var usages = []webcrypto.KeyUsage{
	webcrypto.Sign,
	webcrypto.Verify,
}

type Algorithm struct {
	*AlgorithmParams
}

type CryptoKey struct {
	extractable bool
	algorithm   *Algorithm
	usages      []webcrypto.KeyUsage
	secret      []byte
}

type AlgorithmParams struct {
	Hash   webcrypto.Algorithm
	Length int
}

func New(params *AlgorithmParams) *Algorithm {
	return &Algorithm{
		AlgorithmParams: params,
	}
}

func (c *CryptoKey) ID() string {
	return ""
}

func (c *CryptoKey) Type() webcrypto.KeyType {
	return webcrypto.Secret
}

func (c *CryptoKey) Extractable() bool {
	return c.extractable
}

func (c *CryptoKey) Algorithm() webcrypto.Algorithm {
	return c.algorithm
}

func (c *CryptoKey) Usages() []webcrypto.KeyUsage {
	return c.usages
}

func (a *Algorithm) Name() string {
	return "HMAC"
}

func (a *Algorithm) Decrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) (any, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) DeriveBits(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) DeriveKey(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) Digest(algorithm webcrypto.Algorithm, data io.Reader) ([]byte, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) Encrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) (any, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
	k, ok := key.(*CryptoKey)
	if !ok {
		return nil, webcrypto.ErrNotSupported
	}
	switch format {
	case webcrypto.JsonWebKey:
		return exportKeyAsJsonWebKey(k)
	case webcrypto.Raw:
		return exportKeyAsRaw(k)
	default:
		return nil, webcrypto.ErrNotSupported
	}
}

func exportKeyAsRaw(key *CryptoKey) ([]byte, error) {
	return key.secret, nil
}

func exportKeyAsJsonWebKey(key *CryptoKey) (any, error) {
	m := make(map[string]any)
	m["key_ops"] = key.usages
	m["kty"] = "oct"
	m["ext"] = key.extractable
	switch key.algorithm.Hash.Name() {
	case "SHA-1":
		m["alg"] = "HS1"
	case "SHA-256":
		m["alg"] = "HS256"
	default:
		panic("hmac: invalid hash")
	}
	m["k"] = base64.RawURLEncoding.EncodeToString(key.secret)
	jwk, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(err)
	}
	return jwk, nil
}

func (a *Algorithm) GenerateKey(algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (any, error) {
	alg, ok := algorithm.(*Algorithm)
	if !ok {
		return nil, errors.New("webcrypto: algorithm must be *hmac.Algorithm")
	}
	var blockSize int
	switch alg.Hash.Name() {
	case "SHA-1":
		blockSize = 512
	case "SHA-256":
		blockSize = 512
	default:
		return nil, webcrypto.ErrNotSupported
	}

	if alg.Length != 0 {
		if alg.Length < blockSize {
			return nil, errors.New("length must be above or equal to hash block size")
		}
		if alg.Length%8 != 0 {
			return nil, errors.New("length must be multiples of 8")
		}
	} else {
		alg.Length = blockSize
	}

	// check the key usages
	if len(keyUsages) == 0 {
		return nil, errors.New("webcrypto: at least one key usage is required")
	}
	if err := util.CheckUsages(usages, keyUsages); err != nil {
		return nil, err
	}

	b := make([]byte, alg.Length/8)
	if err := webcrypto.GetRandomValues(b); err != nil {
		return nil, err
	}

	return &CryptoKey{
		algorithm:   alg,
		extractable: extractable,
		usages:      keyUsages,
		secret:      b,
	}, nil
}

func (a *Algorithm) ImportKey(format webcrypto.KeyFormat, keyData any, algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, errors.New("not implemented")
}

func (a *Algorithm) Sign(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (a *Algorithm) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm webcrypto.Algorithm,
	unwrappedKeyAlgorithm webcrypto.Algorithm,
	extractable bool,
	keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) WrapKey(format webcrypto.KeyFormat,
	key webcrypto.CryptoKey,
	wrappingKey webcrypto.CryptoKey,
	wrapAlgorithm webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrNotSupported
}
