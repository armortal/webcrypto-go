package rsa

import (
	"errors"
	"io"
	"math/big"

	"github.com/armortal/webcrypto-go"
)

const (
	rsaOaep string = "RSA-OAEP"
)

func init() {
	webcrypto.RegisterAlgorithm(rsaOaep, func() webcrypto.SubtleCrypto {
		return &algorithm{
			rsaType: rsaOaep,
		}
	})
}

var usages = []webcrypto.KeyUsage{
	webcrypto.Encrypt,
	webcrypto.Decrypt,
	webcrypto.WrapKey,
	webcrypto.UnwrapKey,
}

type algorithm struct {
	rsaType string
}

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
	Exponent big.Int
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
	Hash webcrypto.KeyAlgorithm
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
	// alg       *Algorithm
	ext    bool
	usages []webcrypto.KeyUsage
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

// func (a *Algorithm) Name() string {
// 	return "RSA-OAEP"
// }

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
		keys, err = a.generateKeyOaep(params, extractable, usages...)
	default:
		return nil, webcrypto.NewError(webcrypto.ErrNotSupportedError, "algorithm name is not a valid RSA algorithm")
	}
	return keys, err
}

// generateKeyOaep will generate a new RSA-OAEP key pair.
func (a *algorithm) generateKeyOaep(algorithm *HashedKeyGenParams, extractable bool, keyUsages ...webcrypto.KeyUsage) (*CryptoKeyPair, error) {
	if err := webcrypto.AreUsagesValid([]webcrypto.KeyUsage{
		webcrypto.Encrypt,
		webcrypto.Decrypt,
		webcrypto.WrapKey,
		webcrypto.UnwrapKey,
	}, keyUsages); err != nil {
		return nil, err
	}

	return nil, nil
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
