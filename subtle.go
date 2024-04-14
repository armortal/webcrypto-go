// Copyright 2023-2024 ARMORTAL TECHNOLOGIES PTY LTD

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package webcrypto implements the WebCrypto API specification (https://www.w3.org/TR/WebCryptoAPI/).
package webcrypto

// SubtleCrypto interface provides a set of methods for dealing with low-level cryptographic primitives and
// algorithms.
// See §14. (https://w3c.github.io/webcrypto/#subtlecrypto-interface)
type SubtleCrypto interface {

	// Decrypt will decrypt data using the specified Algorithm with the supplied CryptoKey.
	// See §14.2.2 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-decrypt)
	Decrypt(algorithm *Algorithm, key CryptoKey, data []byte) ([]byte, error)

	// DeriveBits can be used to derive an array of bits from a base key.
	// See  §14.2.8 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-deriveBits)
	DeriveBits(algorithm *Algorithm, baseKey CryptoKey, length uint64) ([]byte, error)

	// DeriveKey can be used to derive a secret key from a master key.
	// See  §14.2.7 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-deriveKey)
	DeriveKey(algorithm *Algorithm, baseKey CryptoKey, derivedKeyType *Algorithm, extractable bool, keyUsages []KeyUsage) (CryptoKey, error)

	// Digrest generates a digest of the given data. A digest is a short fixed-length value
	// derived from some variable-length input. Cryptographic digests should exhibit collision-resistance,
	// meaning that it's hard to come up with two different inputs that have the same digest value.
	// See  §14.2.5 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-digest)
	Digest(algorithm *Algorithm, data []byte) ([]byte, error)

	// Encrypt will encrypt data using the specified AlgorithmIdentifier with the supplied CryptoKey.
	// See §14.2.1 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-encrypt)
	Encrypt(algorithm *Algorithm, key CryptoKey, data []byte) ([]byte, error)

	// ExportKey exports a key: that is, it takes as input a CryptoKey object and gives you the key
	// in an external, portable format.
	// See §14.2.10 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-exportKey)
	ExportKey(format KeyFormat, key CryptoKey) (any, error)

	// GenerateKey generates a new key (for symmetric algorithms) or key pair (for public-key algorithms).
	// See §14.2.6 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-generateKey)
	GenerateKey(algorithm *Algorithm, extractable bool, keyUsages []KeyUsage) (any, error)

	// ImportKey imports a key: that is, it takes as input a key in an external, portable format and
	// gives you a CryptoKey object that you can use in the Web Crypto API.
	// See §14.2.9 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-importKey)
	ImportKey(format KeyFormat, keyData any, algorithm *Algorithm, extractable bool, keyUsages []KeyUsage) (CryptoKey, error)

	// Sign generates a digital signature.
	// See §14.2.3 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-sign)
	Sign(algorithm *Algorithm, key CryptoKey, data []byte) ([]byte, error)

	// UnwrapKey "unwraps" a key. This means that it takes as its input a key that has been exported and
	// then encrypted (also called "wrapped"). It decrypts the key and then imports it, returning a CryptoKey
	// object that can be used in the Web Crypto API.
	// See §14.2.12 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-unwrapKey)
	UnwrapKey(format KeyFormat,
		wrappedKey []byte,
		unwrappingKey CryptoKey,
		unwrapAlgorithm *Algorithm,
		unwrappedKeyAlgorithm *Algorithm,
		extractable bool,
		keyUsages []KeyUsage) (CryptoKey, error)

	// Verify verifies a digital signature.
	// See §14.2.4 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-verify)
	Verify(algorithm *Algorithm, key CryptoKey, signature []byte, data []byte) (bool, error)

	// WrapKey "wraps" a key. This means that it exports the key in an external, portable format, then encrypts
	// the exported key. Wrapping a key helps protect it in untrusted environments, such as inside an otherwise
	// unprotected data store or in transmission over an unprotected network.
	// See §14.2.11 (https://w3c.github.io/webcrypto/#SubtleCrypto-method-wrapKey)
	WrapKey(format KeyFormat, key CryptoKey, wrappingKey CryptoKey, wrapAlgorithm *Algorithm) (any, error)
}

// subtleCrypto is a wrapper around the algorithm implementations.
type subtleCrypto struct{}

func Subtle() SubtleCrypto {
	return &subtleCrypto{}
}

func (s *subtleCrypto) Decrypt(algorithm *Algorithm, key CryptoKey, data []byte) ([]byte, error) {
	algorithmNotNilOrPanic(algorithm)
	subtle, err := getSubtleCrypto(algorithm.Name)
	if err != nil {
		return nil, err
	}
	return subtle.Decrypt(algorithm, key, data)
}

func (s *subtleCrypto) DeriveBits(algorithm *Algorithm, baseKey CryptoKey, length uint64) ([]byte, error) {
	algorithmNotNilOrPanic(algorithm)
	subtle, err := getSubtleCrypto(algorithm.Name)
	if err != nil {
		return nil, err
	}
	return subtle.DeriveBits(algorithm, baseKey, length)
}

func (s *subtleCrypto) DeriveKey(algorithm *Algorithm, baseKey CryptoKey, derivedKeyType *Algorithm, extractable bool, keyUsages []KeyUsage) (CryptoKey, error) {
	algorithmNotNilOrPanic(algorithm)
	subtle, err := getSubtleCrypto(algorithm.Name)
	if err != nil {
		return nil, err
	}
	return subtle.DeriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages)
}

func (s *subtleCrypto) Digest(algorithm *Algorithm, data []byte) ([]byte, error) {
	algorithmNotNilOrPanic(algorithm)
	subtle, err := getSubtleCrypto(algorithm.Name)
	if err != nil {
		return nil, err
	}
	return subtle.Digest(algorithm, data)
}

func (s *subtleCrypto) Encrypt(algorithm *Algorithm, key CryptoKey, data []byte) ([]byte, error) {
	algorithmNotNilOrPanic(algorithm)
	subtle, err := getSubtleCrypto(algorithm.Name)
	if err != nil {
		return nil, err
	}
	return subtle.Encrypt(algorithm, key, data)

}

func (s *subtleCrypto) ExportKey(format KeyFormat, key CryptoKey) (any, error) {
	subtle, err := getSubtleCrypto(key.Algorithm().Name())
	if err != nil {
		return nil, err
	}
	return subtle.ExportKey(format, key)
}

func (s *subtleCrypto) GenerateKey(algorithm *Algorithm, extractable bool, keyUsages []KeyUsage) (any, error) {
	algorithmNotNilOrPanic(algorithm)
	subtle, err := getSubtleCrypto(algorithm.Name)
	if err != nil {
		return nil, err
	}
	return subtle.GenerateKey(algorithm, extractable, keyUsages)
}

func (s *subtleCrypto) ImportKey(format KeyFormat, keyData any, algorithm *Algorithm, extractable bool, keyUsages []KeyUsage) (CryptoKey, error) {
	algorithmNotNilOrPanic(algorithm)
	subtle, err := getSubtleCrypto(algorithm.Name)
	if err != nil {
		return nil, err
	}
	return subtle.ImportKey(format, keyData, algorithm, extractable, keyUsages)
}

func (s *subtleCrypto) Sign(algorithm *Algorithm, key CryptoKey, data []byte) ([]byte, error) {
	algorithmNotNilOrPanic(algorithm)
	subtle, err := getSubtleCrypto(algorithm.Name)
	if err != nil {
		return nil, err
	}
	return subtle.Sign(algorithm, key, data)
}

func (s *subtleCrypto) UnwrapKey(format KeyFormat,
	wrappedKey []byte,
	unwrappingKey CryptoKey,
	unwrapAlgorithm *Algorithm,
	unwrappedKeyAlgorithm *Algorithm,
	extractable bool,
	keyUsages []KeyUsage) (CryptoKey, error) {
	subtle, err := getSubtleCrypto(unwrappingKey.Algorithm().Name())
	if err != nil {
		return nil, err
	}
	return subtle.UnwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages)
}

func (s *subtleCrypto) Verify(algorithm *Algorithm, key CryptoKey, signature []byte, data []byte) (bool, error) {
	algorithmNotNilOrPanic(algorithm)
	subtle, err := getSubtleCrypto(algorithm.Name)
	if err != nil {
		return false, err
	}
	return subtle.Verify(algorithm, key, signature, data)
}

func (s *subtleCrypto) WrapKey(format KeyFormat,
	key CryptoKey,
	wrappingKey CryptoKey,
	wrapAlgorithm *Algorithm) (any, error) {
	subtle, err := getSubtleCrypto(wrappingKey.Algorithm().Name())
	if err != nil {
		return nil, err
	}
	return subtle.WrapKey(format, key, wrappingKey, wrapAlgorithm)
}

// algorithmNotNilOrPanic ensure the algorithm is not nil or panic is thrown.
func algorithmNotNilOrPanic(alg *Algorithm) {
	if alg == nil {
		panic("algorithm cannot be nil")
	}
}
