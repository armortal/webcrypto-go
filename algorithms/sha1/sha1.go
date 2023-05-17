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

package sha1

import (
	"crypto/sha1"
	"io"

	"github.com/armortal/webcrypto-go"
)

type Algorithm struct{}

func New() *Algorithm {
	return &Algorithm{}
}

func (a *Algorithm) Name() string {
	return "SHA-1"
}

func (a *Algorithm) Decrypt(algorithm Algorithm, key webcrypto.CryptoKey, data io.Reader) (any, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) DeriveBits(algorithm Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) DeriveKey(algorithm Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) Digest(algorithm Algorithm, data io.Reader) ([]byte, error) {
	hash := sha1.New()
	b, err := io.ReadAll(data)
	if err != nil {
		return nil, err
	}
	hash.Write(b)
	return hash.Sum(nil), nil
}

func (a *Algorithm) Encrypt(algorithm Algorithm, key webcrypto.CryptoKey, data io.Reader) (any, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) GenerateKey(algorithm Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (any, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) ImportKey(format webcrypto.KeyFormat, keyData any, algorithm Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) Sign(algorithm Algorithm, key webcrypto.CryptoKey, data io.Reader) ([]byte, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm Algorithm,
	unwrappedKeyAlgorithm Algorithm,
	extractable bool,
	keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrNotSupported
}

func (a *Algorithm) WrapKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey, wrappingKey webcrypto.CryptoKey, wrapAlgorithm Algorithm) (any, error) {
	return nil, webcrypto.ErrNotSupported
}
