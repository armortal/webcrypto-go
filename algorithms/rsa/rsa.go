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

// Package rsa implements RSA operations as specified in the algorithm overview
// §19 https://www.w3.org/TR/WebCryptoAPI/#algorithm-overview
package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/util"
)

const (
	rsaOaep string = "RSA-OAEP"
)

var (
	encoding = base64.RawURLEncoding
)

func init() {
	webcrypto.RegisterAlgorithm(rsaOaep, func() webcrypto.SubtleCrypto { return &SubtleCrypto{} })
}

type SubtleCrypto struct{}

type Algorithm struct {
	Name               string
	KeyGenParams       *KeyGenParams
	HashedKeyGenParams *HashedKeyGenParams
	HashedImportParams *HashedImportParams
	OaepParams         *OaepParams
}

func (a *Algorithm) GetName() string {
	return a.Name
}

// KeyGenParams is the model of the dictionary specificationn at
// §20.3 (https://www.w3.org/TR/WebCryptoAPI/#RsaKeyGenParams-dictionary)
type KeyGenParams struct {
	// The length, in bits, of the RSA modulus
	ModulusLength uint64
	// The RSA public exponent
	PublicExponent big.Int
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
	// The hash algorithm to use
	Hash string
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

func (a *SubtleCrypto) Decrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) (any, error) {
	return nil, errors.New("unimplemented")
}

func (a *SubtleCrypto) DeriveBits(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) DeriveKey(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) Digest(algorithm webcrypto.Algorithm, data io.Reader) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) Encrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) (any, error) {
	return nil, errors.New("unimplemented")
}

func (a *SubtleCrypto) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
	ckp, ok := key.(*CryptoKey)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "key must be *rsa.CryptoKey")
	}
	switch format {
	case webcrypto.PKCS8:
		return a.exportKeyPKCS8(ckp)
	case webcrypto.Jwk:
		return a.exportKeyJwk(ckp)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "key format not supported")
	}
}

// exportKeyPKCS8 exports the key as PKCS8 format. The method of exporting as PKCS8 is specified at
// §22.4 exportKey (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations)
func (a *SubtleCrypto) exportKeyPKCS8(key *CryptoKey) ([]byte, error) {
	if !key.isPrivate {
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key is not private")

	}
	return x509.MarshalPKCS8PrivateKey(key.priv)
}

// exportKeyJwk exports the key as webcrypto.JsonWebKey. The method of exporting as jwk is specified at
// §22.4 exportKey (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations)
func (a *SubtleCrypto) exportKeyJwk(key *CryptoKey) (*webcrypto.JsonWebKey, error) {
	jwk := &webcrypto.JsonWebKey{
		Kty:    "RSA",
		Ext:    key.ext,
		KeyOps: key.usages,
	}

	switch key.alg.Name {
	case rsaOaep:
		switch key.alg.Hash {
		case "SHA-1":
			jwk.Alg = "RSA-OAEP"
		case "SHA-256":
			jwk.Alg = "RSA-OAEP-256"
		case "SHA-384":
			jwk.Alg = "RSA-OAEP-384"
		case "SHA-512":
			jwk.Alg = "RSA-OAEP-512"
		default:
			panic("invalid algorithm hash") // we should never have an unknown hash once a key has been generated
		}
	default:
		panic("invalid algorithm name")
	}

	if key.isPrivate {
		jwk.N = encoding.EncodeToString(key.priv.N.Bytes())
		jwk.E = encoding.EncodeToString(big.NewInt(int64(key.priv.E)).Bytes())
		jwk.D = encoding.EncodeToString(key.priv.D.Bytes())
		jwk.P = encoding.EncodeToString(key.priv.Primes[0].Bytes())
		jwk.Q = encoding.EncodeToString(key.priv.Primes[1].Bytes())
		// precompute dp, dq, di
		key.priv.Precompute()
		jwk.Dp = encoding.EncodeToString(key.priv.Precomputed.Dp.Bytes())
		jwk.Dq = encoding.EncodeToString(key.priv.Precomputed.Dq.Bytes())
		jwk.Qi = encoding.EncodeToString(key.priv.Precomputed.Qinv.Bytes())
	} else {
		jwk.N = encoding.EncodeToString(key.pub.N.Bytes())
		jwk.E = encoding.EncodeToString(big.NewInt(int64(key.pub.E)).Bytes())
	}
	return jwk, nil
}

func (a *SubtleCrypto) GenerateKey(algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (any, error) {
	alg, ok := algorithm.(*Algorithm)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "algorithm does *rsa.HashedKeyGenParams")
	}
	var keys *CryptoKeyPair
	var err error
	switch algorithm.GetName() {
	case rsaOaep:
		keys, err = a.generateKeyOaep(alg.HashedKeyGenParams, extractable, keyUsages...)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "algorithm name is not a valid RSA algorithm")
	}
	return keys, err
}

// generateKeyOaep will generate a new RSA-OAEP key pair. The method of generating a key is specified at
// §22.4 generateKey (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations)
func (a *SubtleCrypto) generateKeyOaep(algorithm *HashedKeyGenParams, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKeyPair, error) {
	// If usages contains an entry which is not "encrypt", "decrypt", "wrapKey" or "unwrapKey", then throw a SyntaxError.
	if err := util.AreUsagesValid([]webcrypto.KeyUsage{
		webcrypto.Encrypt,
		webcrypto.Decrypt,
		webcrypto.WrapKey,
		webcrypto.UnwrapKey,
	}, keyUsages); err != nil {
		return nil, err
	}

	// Generate an RSA key pair. The exponent needs to be 65536 because we cannot
	// generate a key with crypto/rsa using a different exponent
	if algorithm.PublicExponent.Int64() != 65537 {
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
			PublicExponent: algorithm.PublicExponent,
		},
		Hash: algorithm.Hash,
	}

	// Create the CryptoKey object for the public key
	pub := &CryptoKey{
		pub:    key.PublicKey,
		alg:    alg,
		ext:    true,
		usages: util.UsageIntersection([]webcrypto.KeyUsage{webcrypto.Encrypt, webcrypto.WrapKey}, keyUsages),
	}

	// Create the CryptoKey object for the private key
	priv := &CryptoKey{
		isPrivate: true,
		alg:       alg,
		ext:       extractable,
		priv:      key,
		usages:    util.UsageIntersection([]webcrypto.KeyUsage{webcrypto.Decrypt, webcrypto.UnwrapKey}, keyUsages),
	}

	return &CryptoKeyPair{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

func (a *SubtleCrypto) ImportKey(format webcrypto.KeyFormat, keyData any, algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, errors.New("unimplemented")
}

func (a *SubtleCrypto) Sign(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm webcrypto.Algorithm,
	unwrappedKeyAlgorithm webcrypto.Algorithm,
	extractable bool,
	keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) Verify(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, signature []byte, data io.Reader) (bool, error) {
	return false, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) WrapKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey, wrappingKey webcrypto.CryptoKey, wrapAlgorithm webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}
