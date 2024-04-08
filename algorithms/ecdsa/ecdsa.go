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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/util"
)

const (
	name string = "ECDSA"

	P256 string = "P-256"
	P384 string = "P-384"
	P521 string = "P-521"
)

// CryptoKey represents an ECDSA cryptography key.
type CryptoKey struct {
	isPrivate bool
	pub       *ecdsa.PublicKey
	priv      *ecdsa.PrivateKey
	alg       *KeyAlgorithm
	ext       bool
	usages    []webcrypto.KeyUsage
}

func (c *CryptoKey) Algorithm() webcrypto.KeyAlgorithm {
	return c.alg
}

func (c *CryptoKey) Extractable() bool {
	return c.ext
}

func (c *CryptoKey) Type() webcrypto.KeyType {
	if c.isPrivate {
		return webcrypto.Private
	}
	return webcrypto.Public
}

func (c *CryptoKey) Usages() []webcrypto.KeyUsage {
	return c.usages
}

type Algorithm struct {
	KeyGenParams *KeyGenParams
}

func (a *Algorithm) GetName() string {
	return name
}

// KeyGenParams represents the parameters available for key generation as specified at
// §23.4 https://www.w3.org/TR/WebCryptoAPI/#dfn-EcKeyGenParams
type KeyGenParams struct {
	NamedCurve string
}

// KeyAlgorithm is the implementation of the dictionary specificationn at
// §23.5 (https://www.w3.org/TR/WebCryptoAPI/#dfn-EcKeyAlgorithm)
type KeyAlgorithm struct {
	namedCurve string
}

func (k *KeyAlgorithm) NamedCurve() string {
	return k.namedCurve
}

func (k *KeyAlgorithm) GetName() string {
	return name
}

type SubtleCrypto struct{}

// Decrypt is not supported.
func (s *SubtleCrypto) Decrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// DeriveBits is not supported.
func (s *SubtleCrypto) DeriveBits(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// DeriveKey is not supported.
func (s *SubtleCrypto) DeriveKey(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// Digest is not supported.
func (s *SubtleCrypto) Digest(algorithm webcrypto.Algorithm, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// Encrypt is not supported.
func (s *SubtleCrypto) Encrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// ExportKey is not supported.
func (s *SubtleCrypto) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// GenerateKey generates a new CryptoKeyPair as per 'Generate Key' operation at
// §23.7 (https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations).
func (s *SubtleCrypto) GenerateKey(algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (any, error) {
	// ensure its the correct algorithm
	alg, ok := algorithm.(*Algorithm)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "algorithm must be *ecdsa.Algorithm")
	}

	// If usages contains an entry which is not "sign" or "verify", then throw a SyntaxError.
	if err := util.AreUsagesValid([]webcrypto.KeyUsage{
		webcrypto.Sign,
		webcrypto.Verify,
	}, keyUsages); err != nil {
		return nil, err
	}

	// validate the KeyGenParams and get the curve
	if alg.KeyGenParams == nil {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "KeyGenParams cannot be nil")
	}

	var crv elliptic.Curve
	switch alg.KeyGenParams.NamedCurve {
	case "P-256":
		crv = elliptic.P256()
	case "P-384":
		crv = elliptic.P384()
	case "P-521":
		crv = elliptic.P521()
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "named curve not supported")
	}

	// generate the key
	key, err := ecdsa.GenerateKey(crv, rand.Reader)
	if err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrOperationError, fmt.Sprintf("failed to generate ecdsa key - %s", err.Error()))
	}

	// create the key algorithm
	kalg := &KeyAlgorithm{
		namedCurve: alg.KeyGenParams.NamedCurve,
	}

	// create the crypto key for the public key
	pub := &CryptoKey{
		isPrivate: false,
		pub:       &key.PublicKey,
		alg:       kalg,
		ext:       true,
		usages: []webcrypto.KeyUsage{
			webcrypto.Verify,
		},
	}

	// create the crypto key for the private key
	priv := &CryptoKey{
		isPrivate: true,
		priv:      key,
		alg:       kalg,
		ext:       extractable,
		usages: []webcrypto.KeyUsage{
			webcrypto.Sign,
		},
	}

	return webcrypto.NewCryptoKeyPair(pub, priv), nil
}

// ImportKey is not supported.
func (s *SubtleCrypto) ImportKey(format webcrypto.KeyFormat, keyData any, algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// ImportKey is not supported.
func (s *SubtleCrypto) Sign(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// ImportKey is not supported.
func (s *SubtleCrypto) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm webcrypto.Algorithm,
	unwrappedKeyAlgorithm webcrypto.Algorithm,
	extractable bool,
	keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// ImportKey is not supported.
func (s *SubtleCrypto) Verify(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, signature []byte, data []byte) (bool, error) {
	return false, webcrypto.ErrMethodNotSupported()
}

// ImportKey is not supported.
func (s *SubtleCrypto) WrapKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey, wrappingKey webcrypto.CryptoKey, wrapAlgorithm webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}
