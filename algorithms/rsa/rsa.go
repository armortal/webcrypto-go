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
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"github.com/armortal/webcrypto-go"
)

const (
	rsaOaep string = "RSA-OAEP"
)

var (
	encoding   = base64.RawURLEncoding
	oaepSubtle *oaepSubtleCrypto
)

func init() {
	oaepSubtle = &oaepSubtleCrypto{}
	webcrypto.RegisterAlgorithm(rsaOaep, oaepSubtle)
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
	name string
	// The length, in bits, of the RSA modulus
	modulusLength uint64
	// The RSA public exponent
	publicExponent *big.Int

	*HashedKeyAlgorithm
}

func (k *KeyAlgorithm) ModulusLength() uint64 {
	return k.modulusLength
}

func (k *KeyAlgorithm) PublicExponent() *big.Int {
	return k.publicExponent
}

func (k *KeyAlgorithm) Name() string {
	return k.name
}

// HashedKeyAlgorithm implements the RsaHashedKeyAlgorithm dictionary specification at
// §20.6 (https://www.w3.org/TR/WebCryptoAPI/#RsaHashedKeyAlgorithm-dictionary)
type HashedKeyAlgorithm struct {
	// The hash algorithm that is used with this key
	Hash string
}

// HashedImportParams implements the RsaHashedImportParams dictionary specification at
// §20.7 (https://www.w3.org/TR/WebCryptoAPI/#RsaHashedImportParams-dictionary)
type HashedImportParams struct {
	// The hash algorithm to use
	Hash string
}

type CryptoKey struct {
	isPrivate bool
	pub       *rsa.PublicKey
	priv      *rsa.PrivateKey
	alg       *KeyAlgorithm
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

func (c *CryptoKey) Algorithm() webcrypto.KeyAlgorithm {
	return c.alg
}

func (c *CryptoKey) Usages() []webcrypto.KeyUsage {
	return c.usages
}
