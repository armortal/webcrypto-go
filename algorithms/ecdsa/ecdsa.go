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

// Package ecdsa implements ECDSA operations as described in the specifications at
// §23 (https://www.w3.org/TR/WebCryptoAPI/#ecdsa).
package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"reflect"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/util"
)

const (
	name string = "ECDSA"

	P256 string = "P-256"
	P384 string = "P-384"
	P521 string = "P-521"
)

var subtle *subtleCrypto

type Params struct {
	Hash string
}

type KeyGenParams struct {
	NamedCurve string
}

type KeyImportParams struct {
	NamedCurve string
}

func init() {
	subtle = &subtleCrypto{}
	webcrypto.RegisterAlgorithm(name, subtle)
}

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

// KeyAlgorithm is the implementation of the dictionary specificationn at
// §23.5 (https://www.w3.org/TR/WebCryptoAPI/#dfn-EcKeyAlgorithm)
type KeyAlgorithm struct {
	namedCurve string
}

func (k *KeyAlgorithm) NamedCurve() string {
	return k.namedCurve
}

func (k *KeyAlgorithm) Name() string {
	return name
}

type subtleCrypto struct{}

// Decrypt is not supported.
func (s *subtleCrypto) Decrypt(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// DeriveBits is not supported.
func (s *subtleCrypto) DeriveBits(algorithm *webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// DeriveKey is not supported.
func (s *subtleCrypto) DeriveKey(algorithm *webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType *webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// Digest is not supported.
func (s *subtleCrypto) Digest(algorithm *webcrypto.Algorithm, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// Encrypt is not supported.
func (s *subtleCrypto) Encrypt(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// ExportKey will export the given key as per 'Export Key' operation at
// §23.7 (https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations).
func (s *subtleCrypto) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
	if !key.Extractable() {
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key not extractable")
	}
	ckp, ok := key.(*CryptoKey)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "key must be *ecdsa.CryptoKey")
	}
	switch format {
	case webcrypto.PKCS8:
		return exportKeyPKCS8(ckp)
	case webcrypto.Jwk:
		return exportKeyJwk(ckp)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "key format not supported")
	}
}

// exportKeyPKCS8 exports the key as PKCS8 format. The method of exporting as PKCS8 is specified at
// §23.7 exportKey (https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations)
func exportKeyPKCS8(key *CryptoKey) ([]byte, error) {
	if !key.isPrivate {
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key is not private")
	}
	return x509.MarshalPKCS8PrivateKey(key.priv)
}

// exportKeyJwk exports the key as webcrypto.JsonWebKey. The method of exporting as jwk is specified at
// §23.7 exportKey (https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations)
func exportKeyJwk(key *CryptoKey) (*webcrypto.JsonWebKey, error) {
	jwk := &webcrypto.JsonWebKey{
		Kty:    "EC",
		Ext:    key.ext,
		Crv:    key.alg.namedCurve,
		KeyOps: []webcrypto.KeyUsage{webcrypto.Verify},
		X:      util.Encoding().EncodeToString(key.pub.X.Bytes()),
		Y:      util.Encoding().EncodeToString(key.pub.Y.Bytes()),
	}

	if key.isPrivate {
		jwk.D = util.Encoding().EncodeToString(key.priv.D.Bytes())
		jwk.KeyOps = []webcrypto.KeyUsage{webcrypto.Sign}
	}

	return jwk, nil
}

// GenerateKey generates a new CryptoKeyPair as per 'Generate Key' operation at
// §23.7 (https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations).
func (s *subtleCrypto) GenerateKey(algorithm *webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (any, error) {
	nameAndParamsOrPanic[*KeyGenParams](algorithm)
	params := algorithm.Params.(*KeyGenParams)

	// If usages contains an entry which is not "sign" or "verify", then throw a SyntaxError.
	if err := util.AreUsagesValid([]webcrypto.KeyUsage{
		webcrypto.Sign,
		webcrypto.Verify,
	}, keyUsages); err != nil {
		return nil, err
	}

	var crv elliptic.Curve
	switch params.NamedCurve {
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
		namedCurve: params.NamedCurve,
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
		pub:       &key.PublicKey,
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
func (s *subtleCrypto) ImportKey(format webcrypto.KeyFormat, keyData any, algorithm *webcrypto.Algorithm, extractable bool, keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	nameAndParamsOrPanic[*KeyImportParams](algorithm)
	params := algorithm.Params.(*KeyImportParams)

	switch format {
	case webcrypto.Jwk:
		jwk, ok := keyData.(*webcrypto.JsonWebKey)
		if !ok {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "keyData must be *webcrypto.JsonWebKey")
		}
		return importKeyJwk(jwk, params, extractable, keyUsages...)
	case webcrypto.PKCS8:
		b, ok := keyData.([]byte)
		if !ok {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "keyData must be []byte")
		}
		return importKeyPKCS8(b, params, extractable, keyUsages...)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "key format not supported")
	}
}

// importKeyPKCS8 will import DER encoded private key. The method of importing a PKCS8 key is specified at
// §22.4 importKey (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations).
//
// Although the specification states that we should first analyse the private key info as we construct our
// crypto key, the standard go library doesn't support access to the underlying pkcs8 struct so
// the implementation in this library will take these values from the algorithm provided in the params.
func importKeyPKCS8(keyData []byte, params *KeyImportParams, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKey, error) {
	if err := util.AreUsagesValid(
		[]webcrypto.KeyUsage{webcrypto.Decrypt, webcrypto.UnwrapKey}, keyUsages); err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		return nil, err
	}

	priv := key.(*ecdsa.PrivateKey)
	switch params.NamedCurve {
	case P256:
		if priv.Curve == elliptic.P256() {
			break
		}
	case P384:
		if priv.Curve == elliptic.P384() {
			break
		}
	case P521:
		if priv.Curve == elliptic.P521() {
			break
		}
	default:
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "named curve mismatch")
	}

	ck := &CryptoKey{
		isPrivate: true,
		alg: &KeyAlgorithm{
			namedCurve: params.NamedCurve,
		},
		priv:   key.(*ecdsa.PrivateKey),
		usages: keyUsages,
		ext:    extractable,
	}

	ck.pub = &ck.priv.PublicKey

	return ck, nil
}

// importKeyJwk will import a JWK. The method of importing JWK is specified at
// §22.4 importKey (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations).
func importKeyJwk(keyData *webcrypto.JsonWebKey, params *KeyImportParams, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKey, error) {
	// If the "kty" field of jwk is not a case-sensitive string match
	// to "EC", then throw a DataError.
	if keyData.Kty != "EC" {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid kty")
	}

	// the 'crv' in the jwk must match the named curve in the provided algorithm
	if keyData.Crv != params.NamedCurve {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "crv mismatch")
	}

	// retrieve the curve
	curve, err := getCurve(params.NamedCurve)
	if err != nil {
		return nil, err
	}

	ck := &CryptoKey{
		isPrivate: false,
		ext:       extractable,
		alg: &KeyAlgorithm{
			namedCurve: params.NamedCurve,
		},
		usages: keyUsages,
	}

	// verify that we have both Y and X attributes for the public key
	if keyData.Y == "" || keyData.X == "" {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "both x and y attributes must be present")
	} else {
		y, err := util.Encoding().DecodeString(keyData.Y)
		if err != nil {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid y: %s", err.Error()))
		}

		x, err := util.Encoding().DecodeString(keyData.X)
		if err != nil {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid y: %s", err.Error()))
		}

		pub := ecdsa.PublicKey{
			Curve: curve,
			Y:     big.NewInt(0).SetBytes(y),
			X:     big.NewInt(0).SetBytes(x),
		}
		ck.pub = &pub
	}

	// If the "d" field of jwk is present and usages contains an entry which is
	// not "sign", then throw a SyntaxError.
	if keyData.D != "" {
		if err := util.AreUsagesValid([]webcrypto.KeyUsage{
			webcrypto.Sign,
		}, keyUsages); err != nil {
			return nil, err
		}

		d, err := util.Encoding().DecodeString(keyData.D)
		if err != nil {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid d: %s", err.Error()))
		}
		ck.isPrivate = true
		ck.priv = &ecdsa.PrivateKey{
			PublicKey: *ck.pub,
			D:         big.NewInt(0).SetBytes(d),
		}
	}

	// If the "key_ops" field of jwk is present, and is invalid according to the requirements
	// of JSON Web Key or does not contain all of the specified usages values, then throw
	// a DataError.
	if ck.isPrivate {
		if len(keyData.KeyOps) != 1 || keyData.KeyOps[0] != webcrypto.Sign {
			return nil, webcrypto.NewError(webcrypto.ErrSyntaxError, "invalid key use")
		}
	} else {
		if len(keyData.KeyOps) != 1 || keyData.KeyOps[0] != webcrypto.Verify {
			return nil, webcrypto.NewError(webcrypto.ErrSyntaxError, "invalid key use")
		}
	}

	// If the "ext" field of jwk is present and has the value false and extractable is true,
	// then throw a DataError.
	if keyData.Ext != extractable {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid ext")
	}

	return ck, nil
}

// Sign will digest the given data as per 'Sign' operation at
// §23.7 (https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations).
func (c *subtleCrypto) Sign(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	nameAndParamsOrPanic[*Params](algorithm)
	params := algorithm.Params.(*Params)

	if key.Type() != webcrypto.Private {
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key must be an *ecdsa.CryptoKey private key")
	}
	// ensure we have a valid key
	pk, ok := key.(*CryptoKey)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key must be an *ecdsa.CryptoKey")
	}

	if key.Type() != webcrypto.Private {
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key must be a private *ecdsa.CryptoKey")
	}

	// get the hasher and digest
	hash, err := util.GetHash(params.Hash)
	if err != nil {
		return nil, err
	}

	_, err = hash.Write(data)
	if err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrOperationError, fmt.Sprintf("failed to digest: %s", err.Error()))
	}

	digest := hash.Sum(nil)

	// We concat both r and s - https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign#ecdsa
	r, s, err := ecdsa.Sign(rand.Reader, pk.priv, digest)
	if err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrOperationError, fmt.Sprintf("failed to sign: %s", err.Error()))
	}

	return append(r.Bytes(), s.Bytes()...), nil
}

// UnwrapKey is not supported.
func (s *subtleCrypto) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm *webcrypto.Algorithm,
	unwrappedKeyAlgorithm *webcrypto.Algorithm,
	extractable bool,
	keyUsages ...webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// Verify will digest the given data as per 'Verify' operation at
// §23.7 (https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations).
func (c *subtleCrypto) Verify(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, signature []byte, data []byte) (bool, error) {
	nameAndParamsOrPanic[*Params](algorithm)
	params := algorithm.Params.(*Params)

	if key.Type() != webcrypto.Public {
		return false, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key must be an *ecdsa.CryptoKey public key")
	}

	// ensure we have a valid key
	pk, ok := key.(*CryptoKey)
	if !ok {
		return false, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key must be an *ecdsa.CryptoKey")
	}

	// get the hasher and digest
	hash, err := util.GetHash(params.Hash)
	if err != nil {
		return false, err
	}

	_, err = hash.Write(data)
	if err != nil {
		return false, webcrypto.NewError(webcrypto.ErrOperationError, fmt.Sprintf("failed to digest: %s", err.Error()))
	}

	digest := hash.Sum(nil)

	r := signature[0:32]
	s := signature[32:64]
	return ecdsa.Verify(pk.pub, digest, big.NewInt(0).SetBytes(r), big.NewInt(0).SetBytes(s)), nil
}

// WrapKey is not supported.
func (s *subtleCrypto) WrapKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey, wrappingKey webcrypto.CryptoKey, wrapAlgorithm *webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

// getCurve will return an elliptic.Curve from the given named curve or error
// if the named curve is not supported.
func getCurve(namedCurve string) (elliptic.Curve, error) {
	switch namedCurve {
	case P256:
		return elliptic.P256(), nil
	case P384:
		return elliptic.P384(), nil
	case P521:
		return elliptic.P521(), nil
	default:
		return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("curve %s not supported", namedCurve))
	}
}

func nameAndParamsOrPanic[T any](alg *webcrypto.Algorithm) T {
	if alg.Name != "ECDSA" {
		panic(fmt.Sprintf("invalid algorithm name %s", name))
	}
	t, ok := alg.Params.(T)
	if !ok {
		panic(fmt.Sprintf("Params must be %s", reflect.TypeFor[T]().Name()))
	}
	return t
}
