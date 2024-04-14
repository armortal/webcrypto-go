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

// Package hmac implements HMAC operations as described in the specifications at
// §29 (https://www.w3.org/TR/WebCryptoAPI/#hmac).
package hmac

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/util"
)

var usages = []webcrypto.KeyUsage{
	webcrypto.Sign,
	webcrypto.Verify,
}

var subtle *subtleCrypto

func init() {
	subtle = &subtleCrypto{}
	webcrypto.RegisterAlgorithm("HMAC", subtle)
}

// subtleCrypto implements webcrypto.SubtleCrypto interface. To access this, use the
// webcrypto.Subtle() method.
type subtleCrypto struct{}

// KeyGenParams represents the dictionary specification of
// §29.5 (https://www.w3.org/TR/WebCryptoAPI/#dfn-HmacKeyGenParams)
type KeyGenParams struct {
	// The inner hash function to use.
	Hash string
	// The length (in bits) of the key to generate. If unspecified, the
	// recommended length will be used, which is the size of the associated hash function's block
	// size.
	Length uint64
}

// ImportParams represents the dictionary specification of
// §29.3 (https://www.w3.org/TR/WebCryptoAPI/#dfn-HmacImportParams)
type ImportParams struct {
	// The inner hash function to use.
	Hash string
	// The length (in bits) of the key.
	Length uint64
}

// KeyAlgorithm represents the dictionary specification of
// §29.4 (https://www.w3.org/TR/WebCryptoAPI/#HmacKeyAlgorithm-dictionary)
type KeyAlgorithm struct {
	hash   string
	length uint64
}

// Hash is the inner hash function to use.
func (k *KeyAlgorithm) Hash() string {
	return k.hash
}

// Length is the length (in bits) of the key.
func (k *KeyAlgorithm) Length() uint64 {
	return k.length
}

// Name is the algorithm name.
func (k *KeyAlgorithm) Name() string {
	return "HMAC"
}

type CryptoKey struct {
	extractable bool
	algorithm   *KeyAlgorithm
	usages      []webcrypto.KeyUsage
	secret      []byte
}

func (c *CryptoKey) Type() webcrypto.KeyType {
	return webcrypto.Secret
}

func (c *CryptoKey) Extractable() bool {
	return c.extractable
}

func (c *CryptoKey) Algorithm() webcrypto.KeyAlgorithm {
	return c.algorithm
}

func (c *CryptoKey) Usages() []webcrypto.KeyUsage {
	return c.usages
}

func (a *CryptoKey) Name() string {
	return "HMAC"
}

// Decrypt is not supported.
func (a *subtleCrypto) Decrypt(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// DeriveBits is not supported.
func (a *subtleCrypto) DeriveBits(algorithm *webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// DeriveKey is not supported.
func (a *subtleCrypto) DeriveKey(algorithm *webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// Digest is not supported.
func (a *subtleCrypto) Digest(algorithm *webcrypto.Algorithm, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// Encrypt is not supported.
func (a *subtleCrypto) Encrypt(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *subtleCrypto) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
	if !key.Extractable() {
		return nil, webcrypto.NewError(webcrypto.ErrOperationError, "key provided is not extractable")
	}
	k, ok := key.(*CryptoKey)
	if !ok {
		return nil, webcrypto.ErrMethodNotSupported()
	}
	return exportKey(format, k)
}

func exportKey(format webcrypto.KeyFormat, key *CryptoKey) (any, error) {
	switch format {
	case webcrypto.Jwk:
		return exportKeyAsJsonWebKey(key)
	case webcrypto.Raw:
		return exportKeyAsRaw(key)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, fmt.Sprintf("format %s not supported", format))
	}
}

func exportKeyAsRaw(key *CryptoKey) ([]byte, error) {
	return key.secret, nil
}

func exportKeyAsJsonWebKey(key *CryptoKey) (*webcrypto.JsonWebKey, error) {
	jwk := &webcrypto.JsonWebKey{
		Kty:    "oct",
		KeyOps: key.usages,
		Ext:    key.extractable,
		K:      base64.RawURLEncoding.EncodeToString(key.secret),
	}

	switch key.algorithm.Hash() {
	case "SHA-1":
		jwk.Alg = "HS1"
	case "SHA-256":
		jwk.Alg = "HS256"
	case "SHA-384":
		jwk.Alg = "HS384"
	case "SHA-512":
		jwk.Alg = "HS512"
	default:
		panic("hmac: invalid hash")
	}

	return jwk, nil
}

func (a *subtleCrypto) GenerateKey(algorithm *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (any, error) {
	params, ok := algorithm.Params.(*KeyGenParams)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "params must be *hmac.KeyGenParams")
	}
	return generateKey(params, extractable, keyUsages)
}

func generateKey(params *KeyGenParams, extractable bool, keyUsages []webcrypto.KeyUsage) (*CryptoKey, error) {
	var blockSize int
	switch params.Hash {
	case "SHA-1":
		blockSize = sha1.BlockSize * 8
	case "SHA-256":
		blockSize = sha256.BlockSize * 8
	case "SHA-384", "SHA-512":
		blockSize = sha512.BlockSize * 8
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "hash algorithm not supported")
	}

	if params.Length != 0 {
		if params.Length < uint64(blockSize) {
			return nil, errors.New("length must be above or equal to hash block size")
		}
		if params.Length%8 != 0 {
			return nil, errors.New("length must be multiples of 8")
		}
	} else {
		params.Length = uint64(blockSize)
	}

	// check the key usages
	if len(keyUsages) == 0 {
		return nil, errors.New("webcrypto: at least one key usage is required")
	}
	if err := util.AreUsagesValid(usages, keyUsages); err != nil {
		return nil, err
	}

	b := make([]byte, params.Length/8)
	if err := webcrypto.GetRandomValues(b); err != nil {
		return nil, err
	}

	return &CryptoKey{
		algorithm: &KeyAlgorithm{
			hash:   params.Hash,
			length: params.Length,
		},
		extractable: extractable,
		usages:      keyUsages,
		secret:      b,
	}, nil
}

func (a *subtleCrypto) ImportKey(format webcrypto.KeyFormat, keyData any, algorithm *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	params, ok := algorithm.Params.(*ImportParams)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "Params must be *hmac.ImportParams")
	}
	if err := util.AreUsagesValid(usages, keyUsages); err != nil {
		return nil, err
	}
	switch format {
	case webcrypto.Jwk:
		return importKeyFromJsonWebKey(keyData.(*webcrypto.JsonWebKey), params, extractable, keyUsages)
	case webcrypto.Raw:
		return importKeyFromRaw(keyData.([]byte), params, extractable, keyUsages)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, fmt.Sprintf("format %s not supported", format))
	}
}

func importKeyFromJsonWebKey(keyData *webcrypto.JsonWebKey, params *ImportParams, extractable bool, keyUsages []webcrypto.KeyUsage) (*CryptoKey, error) {
	if keyData.Kty != "oct" {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "kty is not 'oct'")
	}

	var hashLength int
	switch params.Hash {
	case "SHA-1":
		if keyData.Alg != "HS1" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid alg value")
		}
		hashLength = sha1.BlockSize * 8
	case "SHA-256":
		if keyData.Alg != "HS256" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid alg value")
		}
		hashLength = sha256.BlockSize * 8
	case "SHA-384":
		if keyData.Alg != "HS384" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid alg value")
		}
		hashLength = sha512.BlockSize * 8
	case "SHA-512":
		if keyData.Alg != "HS512" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid alg value")
		}
		hashLength = sha512.BlockSize * 8
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "hash is not supported")
	}

	// If usages is non-empty and the use field of jwk is present and is not "sign", then throw a DataError.
	if len(usages) != 0 {
		if keyData.Use != "sign" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "use must be 'sign'")
		}
	}

	b, err := base64.RawURLEncoding.DecodeString(keyData.K)
	if err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "k is not a valid base64 encoded secret")
	}

	length := len(b) * 8
	if length == 0 {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "k length cannot be 0")
	}

	if hashLength > length {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "k length cannot be less than hash length")
	}

	if params.Length != uint64(length) {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "length provided does not match key length")
	}

	params.Length = uint64(length)

	if keyData.Ext != extractable {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "ext in key does not match value provided")
	}

loop:
	for _, op := range keyData.KeyOps {
		for _, usage := range keyUsages {
			if usage == webcrypto.KeyUsage(op) {
				continue loop
			}
		}
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "key_ops doesn't contain usages provided")
	}

	return &CryptoKey{
		algorithm: &KeyAlgorithm{
			hash:   params.Hash,
			length: params.Length,
		},
		extractable: extractable,
		usages:      keyUsages,
		secret:      b,
	}, nil
}

func importKeyFromRaw(keyData []byte, params *ImportParams, extractable bool, keyUsages []webcrypto.KeyUsage) (*CryptoKey, error) {
	length := len(keyData) * 8
	if length == 0 {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "length must not be 0")
	}

	params.Length = uint64(length)

	return &CryptoKey{
		algorithm: &KeyAlgorithm{
			hash:   params.Hash,
			length: params.Length,
		},
		extractable: extractable,
		secret:      keyData,
		usages:      keyUsages,
	}, nil
}

func (a *subtleCrypto) Sign(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	// if _, ok := algorithm.(*Algorithm); !ok {
	// 	return nil, errors.New("webcrypto: algorithm must be *hmac.Algorithm")
	// }
	k, ok := key.(*CryptoKey)
	if !ok {
		return nil, errors.New("key must be *hmac.CryptoKey")
	}

	var hash func() hash.Hash
	switch k.algorithm.hash {
	case "SHA-1":
		hash = sha1.New
	case "SHA-256":
		hash = sha256.New
	case "SHA-384":
		hash = sha512.New384
	case "SHA-512":
		hash = sha512.New
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "hash not supported")
	}

	h := hmac.New(hash, k.secret)
	h.Write(data)
	return h.Sum(nil), nil
}

// UnwrapKey is not supported.
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
	act, err := a.Sign(algorithm, key, data)
	if err != nil {
		return false, err
	}
	return hmac.Equal(signature, act), nil
}

// WrapKey is not supported.
func (a *subtleCrypto) WrapKey(format webcrypto.KeyFormat,
	key webcrypto.CryptoKey,
	wrappingKey webcrypto.CryptoKey,
	wrapAlgorithm *webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}
