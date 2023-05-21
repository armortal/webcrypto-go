// Copyright 2023 ARMORTAL TECHNOLOGIES PTY LTD

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.package rsa

// Package rsa implementd RSA algorithms as specified in the algorithm overview
// §19 https://www.w3.org/TR/WebCryptoAPI/#algorithm-overview
package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"

	"github.com/armortal/webcrypto-go"
)

const (
	rsaOaep string = "RSA-OAEP"
)

func init() {
	webcrypto.RegisterAlgorithm(rsaOaep, func() webcrypto.SubtleCrypto { return &algorithm{} })
}

type algorithm struct{}

// KeyGenParams is the model of the dictionary specificationn at
// §20.3 (https://www.w3.org/TR/WebCryptoAPI/#RsaKeyGenParams-dictionary)
type KeyGenParams struct {
	Name string
	// The length, in bits, of the RSA modulus
	ModulusLength uint64
	// The RSA public exponent
	Exponent big.Int
}

// GetName implements webcrypto.Algorithm interface.
func (p *KeyGenParams) GetName() string {
	return p.Name
}

// HashedKeyGenParams is the model of the dictionary specificationn at
// §20.4 (https://www.w3.org/TR/WebCryptoAPI/#RsaHashedKeyGenParams-dictionary)
type HashedKeyGenParams struct {
	KeyGenParams
	Hash string
}

// KeyAlgorithm is the implementation of the dictionary specificationn at
// §20.5 (https://www.w3.org/TR/WebCryptoAPI/#RsaKeyAlgorithm-dictionary)
type KeyAlgorithm struct {
	Name string
	// The length, in bits, of the RSA modulus
	ModulusLength uint64
	// The RSA public exponent
	PublicExponent big.Int
}

func (k *KeyAlgorithm) GetName() string {
	return k.Name
}

// OaepParams implements the RsaOaepParams dictionary specification at
// §22.3 https://www.w3.org/TR/WebCryptoAPI/#dfn-RsaOaepParams
type OaepParams struct {
	Label []byte
}

func (p *OaepParams) GetName() string {
	return string(rsaOaep)
}

// HashedKeyAlgorithm implements the RsaHashedKeyAlgorithm dictionary specification at
// §20.6 (https://www.w3.org/TR/WebCryptoAPI/#RsaHashedKeyAlgorithm-dictionary)
type HashedKeyAlgorithm struct {
	KeyAlgorithm
	// The hash algorithm that is used with this key
	Hash string
}

// HashedImportParams implements the RsaHashedImportParams dictionary specification at
// §20.7 (https://www.w3.org/TR/WebCryptoAPI/#RsaHashedImportParams-dictionary)
type HashedImportParams struct {
	Name string
	// The hash algorithm to use
	Hash string
}

func (p *HashedImportParams) GetName() string {
	return p.Name
}

type CryptoKeyPair struct {
	publicKey  *CryptoKey
	privateKey *CryptoKey
}

func (c *CryptoKeyPair) PublicKey() webcrypto.CryptoKey {
	return c.publicKey
}

func (c *CryptoKeyPair) PrivateKey() webcrypto.CryptoKey {
	return c.privateKey
}

type CryptoKey struct {
	isPrivate bool
	pub       rsa.PublicKey
	priv      *rsa.PrivateKey
	alg       *HashedKeyAlgorithm
	ext       bool
	usages    []webcrypto.KeyUsage
}

func (c *CryptoKey) Type() webcrypto.KeyType {
	if c.isPrivate {
		return webcrypto.Private
	}
	return webcrypto.Public
}

func (c *CryptoKey) Extractable() bool {
	return c.ext
}

func (c *CryptoKey) Algorithm() webcrypto.Algorithm {
	return nil
}

func (c *CryptoKey) Usages() []webcrypto.KeyUsage {
	return c.usages
}

func (a *algorithm) Decrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) (any, error) {
	return nil, errors.New("unimplemented")
}

func (a *algorithm) DeriveBits(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *algorithm) DeriveKey(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *algorithm) Digest(algorithm webcrypto.Algorithm, data io.Reader) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *algorithm) Encrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) (any, error) {
	return nil, errors.New("unimplemented")
}

func (a *algorithm) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
	return nil, errors.New("unimplemented")
}

func (a *algorithm) GenerateKey(algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (any, error) {
	params, ok := algorithm.(*HashedKeyGenParams)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "algorithm does *rsa.HashedKeyGenParams")
	}
	var keys *CryptoKeyPair
	var err error
	switch algorithm.GetName() {
	case rsaOaep:
		keys, err = a.generateKeyOaep(params, extractable, keyUsages...)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "algorithm name is not a valid RSA algorithm")
	}
	return keys, err
}

// generateKeyOaep will generate a new RSA-OAEP key pair. The method of generating a key is specified at
// §22.4 generateKey (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations)
func (a *algorithm) generateKeyOaep(algorithm *HashedKeyGenParams, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKeyPair, error) {
	// If usages contains an entry which is not "encrypt", "decrypt", "wrapKey" or "unwrapKey", then throw a SyntaxError.
	if err := webcrypto.AreUsagesValid([]webcrypto.KeyUsage{
		webcrypto.Encrypt,
		webcrypto.Decrypt,
		webcrypto.WrapKey,
		webcrypto.UnwrapKey,
	}, keyUsages); err != nil {
		return nil, err
	}

	// Generate an RSA key pair. The exponent needs to be 65536 because we cannot
	// generate a key with crypto/rsa using a different exponent
	if algorithm.Exponent.Int64() != 65537 {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "exponent must be 65536")
	}

	key, err := rsa.GenerateKey(rand.Reader, int(algorithm.ModulusLength))
	if err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrOperationError, err.Error())
	}

	// Create the new HashedKeyAlgorithm object.
	alg := &HashedKeyAlgorithm{
		KeyAlgorithm: KeyAlgorithm{
			Name:           rsaOaep,
			ModulusLength:  algorithm.ModulusLength,
			PublicExponent: algorithm.Exponent,
		},
		Hash: algorithm.Hash,
	}

	// Create the CryptoKey object for the public key
	pub := &CryptoKey{
		pub:    key.PublicKey,
		alg:    alg,
		ext:    true,
		usages: webcrypto.UsageIntersection([]webcrypto.KeyUsage{webcrypto.Encrypt, webcrypto.WrapKey}, keyUsages),
	}

	// Create the CryptoKey object for the private key
	priv := &CryptoKey{
		isPrivate: true,
		ext:       extractable,
		priv:      key,
		usages:    webcrypto.UsageIntersection([]webcrypto.KeyUsage{webcrypto.Decrypt, webcrypto.UnwrapKey}, keyUsages),
	}

	return &CryptoKeyPair{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

func (a *algorithm) ImportKey(format webcrypto.KeyFormat, keyData []byte, algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, errors.New("unimplemented")
}

func (a *algorithm) Sign(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *algorithm) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm webcrypto.Algorithm,
	unwrappedKeyAlgorithm webcrypto.Algorithm,
	extractable bool,
	keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *algorithm) Verify(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, signature []byte, data []byte) (bool, error) {
	return false, webcrypto.ErrMethodNotSupported()
}

func (a *algorithm) WrapKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey, wrappingKey webcrypto.CryptoKey, wrapAlgorithm webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}
