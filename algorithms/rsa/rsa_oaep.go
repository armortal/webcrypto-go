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

// Package rsa implements RSA operations;
// RSA-OAEP as specified in §30 (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep).
package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/util"
)

// OaepParams implements the RsaOaepParams dictionary specification at
// §22.3 https://www.w3.org/TR/WebCryptoAPI/#dfn-RsaOaepParams
type OaepParams struct {
	Label []byte
}

// oaepSubtleCrypto implements the webcrypto.SubtleCrypto interface and
// the available operations specified at
// §22.2 (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-registration)
type oaepSubtleCrypto struct{}

func (a *oaepSubtleCrypto) Decrypt(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	if algorithm.Name != rsaOaep {
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "encrypt not supported")
	}
	params := algorithm.Params.(*OaepParams)

	k, ok := key.(*CryptoKey)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "key must be *rsa.CryptoKey")
	}

	if !k.isPrivate {
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key must be private")
	}

	hash, err := util.GetHash(k.alg.Hash)
	if err != nil {
		return nil, err
	}
	// label := make([]byte, 0)
	// if alg.OaepParams != nil {
	// label := params.Label
	// }

	msg, err := rsa.DecryptOAEP(hash, rand.Reader, k.priv, data, params.Label)
	if err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrOperationError, err.Error())
	}

	return msg, nil
}

func (a *oaepSubtleCrypto) DeriveBits(algorithm *webcrypto.Algorithm, baseKey webcrypto.CryptoKey, length uint64) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *oaepSubtleCrypto) DeriveKey(algorithm *webcrypto.Algorithm, baseKey webcrypto.CryptoKey, derivedKeyType *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *oaepSubtleCrypto) Digest(algorithm *webcrypto.Algorithm, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *oaepSubtleCrypto) Encrypt(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	// alg, err := getAlgorithm(algorithm)
	// if err != nil {
	// 	return nil, err
	// }
	if algorithm.Name != rsaOaep {
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "encrypt not supported")
	}
	params := algorithm.Params.(*OaepParams)

	k, ok := key.(*CryptoKey)
	if !ok {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "key must be *rsa.CryptoKey")
	}

	if k.isPrivate {
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key must be public")
	}

	hash, err := util.GetHash(k.alg.Hash)
	if err != nil {
		return nil, err
	}

	// label := make([]byte, 0)
	// if alg.OaepParams != nil {
	// label = params.Label
	// }

	b, err := rsa.EncryptOAEP(hash, rand.Reader, k.pub, data, params.Label)
	if err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrOperationError, err.Error())
	}

	return b, nil
}

func (a *oaepSubtleCrypto) ExportKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey) (any, error) {
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
func (a *oaepSubtleCrypto) exportKeyPKCS8(key *CryptoKey) ([]byte, error) {
	if !key.isPrivate {
		return nil, webcrypto.NewError(webcrypto.ErrInvalidAccessError, "key is not private")

	}
	return x509.MarshalPKCS8PrivateKey(key.priv)
}

// exportKeyJwk exports the key as webcrypto.JsonWebKey. The method of exporting as jwk is specified at
// §22.4 exportKey (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations)
func (a *oaepSubtleCrypto) exportKeyJwk(key *CryptoKey) (*webcrypto.JsonWebKey, error) {
	jwk := &webcrypto.JsonWebKey{
		Kty:    "RSA",
		Ext:    key.ext,
		KeyOps: key.usages,
		Use:    "enc",
	}

	switch key.alg.name {
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

func (a *oaepSubtleCrypto) GenerateKey(algorithm *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (any, error) {
	// alg, ok := algorithm.(*Algorithm)
	// if !ok {
	// 	return nil, webcrypto.NewError(webcrypto.ErrDataError, "algorithm must be *rsa.HashedKeyGenParams")
	// }
	params := algorithm.Params.(*HashedKeyGenParams)
	var keys webcrypto.CryptoKeyPair
	var err error
	switch algorithm.Name {
	case rsaOaep:
		keys, err = a.generateKeyOaep(params, extractable, keyUsages)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "algorithm name is not a valid RSA algorithm")
	}
	return keys, err
}

// generateKeyOaep will generate a new RSA-OAEP key pair. The method of generating a key is specified at
// §22.4 generateKey (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations)
func (a *oaepSubtleCrypto) generateKeyOaep(algorithm *HashedKeyGenParams, extractable bool, keyUsages []webcrypto.KeyUsage) (webcrypto.CryptoKeyPair, error) {
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
	alg := &KeyAlgorithm{
		name:           rsaOaep,
		modulusLength:  algorithm.ModulusLength,
		publicExponent: &algorithm.PublicExponent,
		HashedKeyAlgorithm: &HashedKeyAlgorithm{
			Hash: algorithm.Hash,
		},
	}

	// Create the CryptoKey object for the public key
	pub := &CryptoKey{
		pub:    &key.PublicKey,
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

	return webcrypto.NewCryptoKeyPair(pub, priv), nil
}

func (a *oaepSubtleCrypto) ImportKey(format webcrypto.KeyFormat, keyData any, algorithm *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	// alg, ok := algorithm.(*Algorithm)
	// if !ok {
	// 	return nil, webcrypto.NewError(webcrypto.ErrDataError, "algorithm must be *rsa.Algorithm")
	// }
	// if alg.HashedImportParams == nil {
	// 	return nil, webcrypto.NewError(webcrypto.ErrDataError, "HashedImportParams is required")
	// }

	switch format {
	case webcrypto.Jwk:
		jwk, ok := keyData.(*webcrypto.JsonWebKey)
		if !ok {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "keyData must be *webcrypto.JsonWebKey")
		}
		return a.importKeyJwk(jwk, algorithm, extractable, keyUsages)
	case webcrypto.PKCS8:
		b, ok := keyData.([]byte)
		if !ok {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "keyData must be []byte")
		}
		return a.importKeyPKCS8(b, algorithm, extractable, keyUsages)
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
func (a *oaepSubtleCrypto) importKeyPKCS8(keyData []byte, algorithm *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (*CryptoKey, error) {
	if err := util.AreUsagesValid(
		[]webcrypto.KeyUsage{webcrypto.Decrypt, webcrypto.UnwrapKey}, keyUsages); err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		return nil, err
	}

	ck := &CryptoKey{
		isPrivate: true,
		usages:    keyUsages,
		ext:       extractable,
	}

	switch algorithm.Name {
	case rsaOaep:
		params := algorithm.Params.(*HashedImportParams)
		r := key.(*rsa.PrivateKey)
		ck.priv = r
		ck.alg = &KeyAlgorithm{
			name: rsaOaep,
			HashedKeyAlgorithm: &HashedKeyAlgorithm{
				Hash: params.Hash,
			},
			modulusLength:  uint64(r.N.BitLen()),
			publicExponent: big.NewInt(int64(r.E)),
		}
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "algorithm name not supported")
	}

	return ck, nil
}

// importKeyJwk will import a JWK. The method of importing JWK is specified at
// §22.4 importKey (https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations).
func (a *oaepSubtleCrypto) importKeyJwk(keyData *webcrypto.JsonWebKey, algorithm *webcrypto.Algorithm, extractable bool, keyUsages []webcrypto.KeyUsage) (*CryptoKey, error) {
	// If the "d" field of jwk is present and usages contains an entry which is
	// not "decrypt" or "unwrapKey", then throw a SyntaxError.
	if keyData.D != "" {
		if err := util.AreUsagesValid([]webcrypto.KeyUsage{
			webcrypto.Decrypt, webcrypto.UnwrapKey,
		}, keyUsages); err != nil {
			return nil, err
		}
	} else {
		// If the "d" field of jwk is not present and usages contains an entry which is not
		// "encrypt" or "wrapKey", then throw a SyntaxError.
		if err := util.AreUsagesValid([]webcrypto.KeyUsage{
			webcrypto.Encrypt, webcrypto.WrapKey,
		}, keyUsages); err != nil {
			return nil, err
		}
	}

	// If the "kty" field of jwk is not a case-sensitive string match
	// to "RSA", then throw a DataError.
	if keyData.Kty != "RSA" {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid kty")
	}

	// If usages is non-empty and the "use" field of jwk is present and is
	// not a case-sensitive string match to "enc", then throw a DataError.
	if len(keyUsages) > 0 {
		if keyData.Use != "enc" {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid use")
		}
	}

	// If the "key_ops" field of jwk is present, and is invalid according to the requirements
	// of JSON Web Key or does not contain all of the specified usages values, then throw
	// a DataError.
	if len(keyData.KeyOps) > 0 {
		if err := util.AreUsagesValid(keyUsages, keyData.KeyOps); err != nil {
			return nil, err
		}
	}

	// If the "ext" field of jwk is present and has the value false and extractable is true,
	// then throw a DataError.
	if keyData.Ext != extractable {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid ext")
	}

	hash := ""
	if keyData.Alg != "" {
		switch keyData.Alg {
		case "RSA-OAEP":
			hash = "SHA-1"
		case "RSA-OAEP-256":
			hash = "SHA-256"
		case "RSA-OAEP-384":
			hash = "SHA-384"
		case "RSA-OAEP-512":
			hash = "SHA-512"
		default:
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "invalid alg")
		}
	}

	// TODO normalize algorithm
	// extract the public key attributes
	ck := &CryptoKey{
		isPrivate: false,
		ext:       extractable,
		alg: &KeyAlgorithm{
			name: "RSA-OAEP",
			HashedKeyAlgorithm: &HashedKeyAlgorithm{
				Hash: hash,
			},
		},
		usages: keyUsages,
	}

	pub := rsa.PublicKey{}
	n, err := encoding.DecodeString(keyData.N)
	if err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid n: %s", err.Error()))
	}
	pub.N = big.NewInt(0).SetBytes(n)

	e, err := encoding.DecodeString(keyData.E)
	if err != nil {
		return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid e: %s", err.Error()))
	}
	pub.E = int(big.NewInt(0).SetBytes(e).Int64())
	ck.alg.modulusLength = uint64(pub.N.BitLen())
	ck.alg.publicExponent = big.NewInt(int64(pub.E))
	ck.pub = &pub

	// Extract private data if it exists
	if keyData.D != "" {
		ck.isPrivate = true
		priv := rsa.PrivateKey{
			PublicKey: pub,
		}
		d, err := encoding.DecodeString(keyData.D)
		if err != nil {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid d: %s", err.Error()))
		}
		priv.D = big.NewInt(0).SetBytes(d)

		priv.Primes = make([]*big.Int, 2)
		p, err := encoding.DecodeString(keyData.P)
		if err != nil {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid p: %s", err.Error()))
		}
		priv.Primes[0] = big.NewInt(0).SetBytes(p)

		q, err := encoding.DecodeString(keyData.Q)
		if err != nil {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid q: %s", err.Error()))
		}
		priv.Primes[1] = big.NewInt(0).SetBytes(q)

		// Lets precompute dp, dq, qi and check that the data in the jwk is correct
		priv.Precompute()

		dp, err := encoding.DecodeString(keyData.Dp)
		if err != nil {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid dp: %s", err.Error()))
		}
		if priv.Precomputed.Dp.Cmp(big.NewInt(0).SetBytes(dp)) != 0 {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "dp value does not match precomputed value")
		}

		dq, err := encoding.DecodeString(keyData.Dq)
		if err != nil {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid dq: %s", err.Error()))
		}
		if priv.Precomputed.Dq.Cmp(big.NewInt(0).SetBytes(dq)) != 0 {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "dq value does not match precomputed value")
		}

		qi, err := encoding.DecodeString(keyData.Qi)
		if err != nil {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, fmt.Sprintf("invalid qi: %s", err.Error()))
		}
		if priv.Precomputed.Qinv.Cmp(big.NewInt(0).SetBytes(qi)) != 0 {
			return nil, webcrypto.NewError(webcrypto.ErrDataError, "qi value does not match precomputed value")
		}

		ck.priv = &priv
	}
	return ck, nil
}

func (a *oaepSubtleCrypto) Sign(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, data []byte) ([]byte, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *oaepSubtleCrypto) UnwrapKey(format webcrypto.KeyFormat,
	wrappedKey []byte,
	unwrappingKey webcrypto.CryptoKey,
	unwrapAlgorithm *webcrypto.Algorithm,
	unwrappedKeyAlgorithm *webcrypto.Algorithm,
	extractable bool,
	keyUsages []webcrypto.KeyUsage) (webcrypto.CryptoKey, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}

func (a *oaepSubtleCrypto) Verify(algorithm *webcrypto.Algorithm, key webcrypto.CryptoKey, signature []byte, data []byte) (bool, error) {
	return false, webcrypto.ErrMethodNotSupported()
}

func (a *oaepSubtleCrypto) WrapKey(format webcrypto.KeyFormat, key webcrypto.CryptoKey, wrappingKey webcrypto.CryptoKey, wrapAlgorithm *webcrypto.Algorithm) (any, error) {
	return nil, webcrypto.ErrMethodNotSupported()
}
