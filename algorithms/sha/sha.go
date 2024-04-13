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

// Package sha implements the SHA operations as specified in
// §30 (https://www.w3.org/TR/WebCryptoAPI/#sha)
package sha

import (
	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/util"
)

const (
	sha_1   string = "SHA-1"
	sha_256 string = "SHA-256"
	sha_384 string = "SHA-384"
	sha_512 string = "SHA-512"
)

func init() {
	webcrypto.RegisterAlgorithm(sha_1, &subtleCrypto{name: sha_1})
	webcrypto.RegisterAlgorithm(sha_256, &subtleCrypto{name: sha_256})
	webcrypto.RegisterAlgorithm(sha_384, &subtleCrypto{name: sha_384})
	webcrypto.RegisterAlgorithm(sha_512, &subtleCrypto{name: sha_512})
}

type subtleCrypto struct {
	// name is the hasher that this crypto implementation uses e.g. SHA-1, SHA-256 etc.
	name string
}

func (s *subtleCrypto) Decrypt(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (s *subtleCrypto) DeriveBits(algorithm *webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (s *subtleCrypto) DeriveKey(algorithm *webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (s *subtleCrypto) Digest(algorithm *webcrypto.Algorithm, data []byte) ([]byte, error) {
	util.NotNilOrPanic("algorithm", algorithm)
	if algorithm.Name != s.name {
		panic("hash mismatch")
	}
	hash, err := util.GetHash(algorithm.Name)
	if err != nil {
		return nil, err
	}
	hash.Write(data)
	return hash.Sum(nil), nil
}

func (a *subtleCrypto) Encrypt(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *subtleCrypto) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *subtleCrypto) GenerateKey(algorithm *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *subtleCrypto) ImportKey(format webcrypto.KeyFormat, keyData any, algorithm *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *subtleCrypto) Sign(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *subtleCrypto) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm *webcrypto.Algorithm,
	unwrappedKeyAlgorithm *webcrypto.Algorithm,
	extractable bool,
	keyUsages []webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *subtleCrypto) Verify(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, signature []byte, data []byte) (bool, error) {
	return false, webcrypto.ErrMethodNotSupported()
}

func (a *subtleCrypto) WrapKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey, wrappingKey webcrypto.CryptoKey, wrapAlgorithm *webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}
