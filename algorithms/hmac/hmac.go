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
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/util"
)

var usages = []webcrypto.KeyUsage{
	webcrypto.Sign,
	webcrypto.Verify,
}

type Algorithm struct {
	webcrypto.SubtleCrypto
	Hash   webcrypto.Algorithm
	Length int
}

type CryptoKey struct {
	extractable bool
	algorithm   *Algorithm
	usages      []webcrypto.KeyUsage
	secret      []byte
}

type options struct {
	Hash   webcrypto.Algorithm
	Length int
}

type Option func(o *options)

func WithHash(hash webcrypto.Algorithm) Option {
	return func(o *options) {
		o.Hash = hash
	}
}

func WithLength(length int) Option {
	return func(o *options) {
		o.Length = length
	}
}

func New(opts ...Option) *Algorithm {
	o := &options{
		Hash:   nil,
		Length: 0,
	}
	for _, apply := range opts {
		apply(o)
	}
	return &Algorithm{
		Hash:   o.Hash,
		Length: o.Length,
	}
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
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *Algorithm) DeriveBits(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *Algorithm) DeriveKey(algorithm webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *Algorithm) Digest(algorithm webcrypto.Algorithm, data io.Reader) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *Algorithm) Encrypt(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *Algorithm) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
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

	switch key.algorithm.Hash.Name() {
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

func (a *Algorithm) GenerateKey(algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (any, error) {
	alg, ok := algorithm.(*Algorithm)
	if !ok {
		return nil, errors.New("webcrypto: algorithm must be *hmac.Algorithm")
	}
	return generateKey(alg, extractable, keyUsages...)
}

func generateKey(algorithm *Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKey, error) {
	var blockSize int
	switch algorithm.Hash.Name() {
	case "SHA-1":
		blockSize = sha1.BlockSize * 8
	case "SHA-256":
		blockSize = sha256.BlockSize * 8
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "hash algorithm not supported")
	}

	if algorithm.Length != 0 {
		if algorithm.Length < blockSize {
			return nil, errors.New("length must be above or equal to hash block size")
		}
		if algorithm.Length%8 != 0 {
			return nil, errors.New("length must be multiples of 8")
		}
	} else {
		algorithm.Length = blockSize
	}

	// check the key usages
	if len(keyUsages) == 0 {
		return nil, errors.New("webcrypto: at least one key usage is required")
	}
	if ok := util.AreUsagesValid(usages, keyUsages); !ok {
		return nil, webcrypto.ErrInvalidUsages(usages...)
	}

	b := make([]byte, algorithm.Length/8)
	if err := webcrypto.GetRandomValues(b); err != nil {
		return nil, err
	}

	return &CryptoKey{
		algorithm:   algorithm,
		extractable: extractable,
		usages:      keyUsages,
		secret:      b,
	}, nil
}

func (a *Algorithm) ImportKey(format webcrypto.KeyFormat, keyData []byte, algorithm webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	alg, ok := algorithm.(*Algorithm)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "algorithm must be *hmac.Algorithm")
	}
	return importKey(format, keyData, alg, extractable, usages...)
}

func importKey(format webcrypto.KeyFormat, keyData []byte, algorithm *Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKey, error) {
	if ok := util.AreUsagesValid(usages, keyUsages); !ok {
		return nil, webcrypto.ErrInvalidUsages(usages...)
	}
	switch format {
	case webcrypto.Jwk:
		return importKeyFromJsonWebKey(keyData, algorithm, extractable, keyUsages...)
	case webcrypto.Raw:
		return importKeyFromRaw(keyData, algorithm, extractable, keyUsages...)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, fmt.Sprintf("format %s not supported", format))
	}
}

func importKeyFromJsonWebKey(keyData []byte, algorithm *Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKey, error) {
	var jwk webcrypto.JsonWebKey
	if err := json.Unmarshal(keyData, &jwk); err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, err.Error())
	}

	if jwk.Kty != "oct" {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "kty is not 'oct'")
	}

	var hashLength int
	switch algorithm.Hash.Name() {
	case "SHA-1":
		if jwk.Alg != "HS1" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid alg value")
		}
		hashLength = sha1.BlockSize * 8
	case "SHA-256":
		if jwk.Alg != "HS256" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid alg value")
		}
		hashLength = sha256.BlockSize * 8
	case "SHA-384":
		if jwk.Alg != "HS384" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid alg value")
		}
		hashLength = sha512.BlockSize * 8
	case "SHA-512":
		if jwk.Alg != "HS512" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid alg value")
		}
		hashLength = sha512.BlockSize * 8
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "hash is not supported")
	}

	// If usages is non-empty and the use field of jwk is present and is not "sign", then throw a DataError.
	if len(usages) != 0 {
		if jwk.Use != "sign" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "use must be 'sign'")
		}
	}

	b, err := base64.RawURLEncoding.DecodeString(jwk.K)
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

	if algorithm.Length != length {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "length provided does not match key length")
	}

	algorithm.Length = length

	if jwk.Ext != extractable {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "ext in key does not match value provided")
	}

loop:
	for _, op := range jwk.KeyOps {
		for _, usage := range keyUsages {
			if usage == webcrypto.KeyUsage(op) {
				continue loop
			}
		}
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "key_ops doesn't contain usages provided")
	}

	return &CryptoKey{
		algorithm:   algorithm,
		extractable: extractable,
		usages:      keyUsages,
		secret:      b,
	}, nil
}

func importKeyFromRaw(keyData any, algorithm *Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKey, error) {
	secret, ok := keyData.([]byte)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "keyData must be []byte")
	}

	length := len(secret) * 8
	if length == 0 {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "length must not be 0")
	}

	algorithm.Length = length

	return &CryptoKey{
		algorithm:   algorithm,
		extractable: extractable,
		secret:      secret,
		usages:      keyUsages,
	}, nil
}

func (a *Algorithm) Sign(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, data io.Reader) ([]byte, error) {
	if _, ok := algorithm.(*Algorithm); !ok {
		return nil, errors.New("webcrypto: algorithm must be *hmac.Algorithm")
	}

	k, ok := key.(*CryptoKey)
	if !ok {
		return nil, errors.New("key must be *hmac.CryptoKey")
	}

	var hash func() hash.Hash
	switch k.algorithm.Hash.Name() {
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
	b, err := io.ReadAll(data)
	if err != nil {
		return nil, err
	}
	h.Write(b)
	return h.Sum(nil), nil
}

func (a *Algorithm) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm webcrypto.Algorithm,
	unwrappedKeyAlgorithm webcrypto.Algorithm,
	extractable bool,
	keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *Algorithm) Verify(algorithm webcrypto.Algorithm, key webcrypto.CryptoKey, signature []byte, data []byte) (bool, error) {
	act, err := a.Sign(algorithm, key, bytes.NewReader(data))
	if err != nil {
		return false, err
	}
	return hmac.Equal(signature, act), nil
}

func (a *Algorithm) WrapKey(format webcrypto.KeyFormat,
	key webcrypto.CryptoKey,
	wrappingKey webcrypto.CryptoKey,
	wrapAlgorithm webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}
