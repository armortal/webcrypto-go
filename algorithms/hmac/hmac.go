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

func init() {
	webcrypto.RegisterAlgorithm("HMAC", func() webcrypto.SubtleCrypto { return &SubtleCrypto{} })
}

type SubtleCrypto struct {
	webcrypto.SubtleCrypto
	Hash   webcrypto.Algorithm
	Length int
}

type CryptoKey struct {
	extractable bool
	algorithm   *KeyAlgorithm
	usages      []webcrypto.KeyUsage
	secret      []byte
}

type Algorithm struct {
	Name         string
	KeyGenParams *KeyGenParams
	ImportParams *ImportParams
}

func (a *Algorithm) GetName() string {
	return a.Name
}

type KeyGenParams struct {
	Hash   string
	Length uint64
}

type ImportParams struct {
	Hash   string
	Length uint64
}

type KeyAlgorithm struct {
	Hash   string
	Length uint64
}

func (k *KeyAlgorithm) GetName() string {
	return "HMAC"
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

func (a *SubtleCrypto) Name() string {
	return "HMAC"
}

func (a *SubtleCrypto) Decrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) DeriveBits(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) DeriveKey(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) Digest(algorithm webcrypto.Algorithm, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) Encrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
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

	switch key.algorithm.Hash {
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

func (a *SubtleCrypto) GenerateKey(algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (any, error) {
	alg, ok := algorithm.(*Algorithm)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "algorithm must be *hmac.Algorithm")
	}
	if alg.KeyGenParams == nil {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "*KeyGenParams must be provided")
	}
	return generateKey(alg, extractable, keyUsages...)
}

func generateKey(algorithm *Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKey, error) {
	var blockSize int
	switch algorithm.KeyGenParams.Hash {
	case "SHA-1":
		blockSize = sha1.BlockSize * 8
	case "SHA-256":
		blockSize = sha256.BlockSize * 8
	case "SHA-384", "SHA-512":
		blockSize = sha512.BlockSize * 8
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "hash algorithm not supported")
	}

	if algorithm.KeyGenParams.Length != 0 {
		if algorithm.KeyGenParams.Length < uint64(blockSize) {
			return nil, errors.New("length must be above or equal to hash block size")
		}
		if algorithm.KeyGenParams.Length%8 != 0 {
			return nil, errors.New("length must be multiples of 8")
		}
	} else {
		algorithm.KeyGenParams.Length = uint64(blockSize)
	}

	// check the key usages
	if len(keyUsages) == 0 {
		return nil, errors.New("webcrypto: at least one key usage is required")
	}
	if err := util.AreUsagesValid(usages, keyUsages); err != nil {
		return nil, err
	}

	b := make([]byte, algorithm.KeyGenParams.Length/8)
	if err := webcrypto.GetRandomValues(b); err != nil {
		return nil, err
	}

	return &CryptoKey{
		algorithm: &KeyAlgorithm{
			Hash:   algorithm.KeyGenParams.Hash,
			Length: algorithm.KeyGenParams.Length,
		},
		extractable: extractable,
		usages:      keyUsages,
		secret:      b,
	}, nil
}

func (a *SubtleCrypto) ImportKey(format webcrypto.KeyFormat, keyData any, algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	alg, ok := algorithm.(*Algorithm)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "algorithm must be *hmac.Algorithm")
	}
	if err := util.AreUsagesValid(usages, keyUsages); err != nil {
		return nil, err
	}
	switch format {
	case webcrypto.Jwk:
		return importKeyFromJsonWebKey(keyData.(*webcrypto.JsonWebKey), alg, extractable, keyUsages...)
	case webcrypto.Raw:
		return importKeyFromRaw(keyData.([]byte), alg, extractable, keyUsages...)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, fmt.Sprintf("format %s not supported", format))
	}
}

func importKeyFromJsonWebKey(keyData *webcrypto.JsonWebKey, algorithm *Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKey, error) {
	if keyData.Kty != "oct" {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "kty is not 'oct'")
	}

	var hashLength int
	switch algorithm.ImportParams.Hash {
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

	if algorithm.ImportParams.Length != uint64(length) {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "length provided does not match key length")
	}

	algorithm.ImportParams.Length = uint64(length)

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
			Hash:   algorithm.ImportParams.Hash,
			Length: algorithm.ImportParams.Length,
		},
		extractable: extractable,
		usages:      keyUsages,
		secret:      b,
	}, nil
}

func importKeyFromRaw(keyData []byte, algorithm *Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKey, error) {
	length := len(keyData) * 8
	if length == 0 {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "length must not be 0")
	}

	algorithm.ImportParams.Length = uint64(length)

	return &CryptoKey{
		algorithm: &KeyAlgorithm{
			Hash:   algorithm.ImportParams.Hash,
			Length: algorithm.ImportParams.Length,
		},
		extractable: extractable,
		secret:      keyData,
		usages:      keyUsages,
	}, nil
}

func (a *SubtleCrypto) Sign(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	if _, ok := algorithm.(*Algorithm); !ok {
		return nil, errors.New("webcrypto: algorithm must be *hmac.Algorithm")
	}

	k, ok := key.(*CryptoKey)
	if !ok {
		return nil, errors.New("key must be *hmac.CryptoKey")
	}

	var hash func() hash.Hash
	switch k.algorithm.Hash {
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

func (a *SubtleCrypto) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm webcrypto.Algorithm,
	unwrappedKeyAlgorithm webcrypto.Algorithm,
	extractable bool,
	keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *SubtleCrypto) Verify(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, signature []byte, data []byte) (bool, error) {
	act, err := a.Sign(algorithm, key, data)
	if err != nil {
		return false, err
	}
	return hmac.Equal(signature, act), nil
}

func (a *SubtleCrypto) WrapKey(format webcrypto.KeyFormat,
	key webcrypto.CryptoKey,
	wrappingKey webcrypto.CryptoKey,
	wrapAlgorithm webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}
