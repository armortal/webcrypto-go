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

package webcrypto

type KeyUsage string
type KeyType string

const (
	Encrypt    KeyUsage = "encrypt"    // The key may be used to encrypt messages.
	Decrypt    KeyUsage = "decrypt"    // The key may be used to decrypt messages.
	Sign       KeyUsage = "sign"       // The key may be used to sign messages.
	Verify     KeyUsage = "verify"     // The key may be used to verify signatures.
	DeriveKey  KeyUsage = "deriveKey"  // The key may be used in deriving a new key.
	DeriveBits KeyUsage = "deriveBits" // The key may be used in deriving bits.
	WrapKey    KeyUsage = "wrapKey"    // The key may be used to wrap a key.
	UnwrapKey  KeyUsage = "unwrapKey"  // The key may be used to unwrap a key.

	Secret  KeyType = "secret"
	Private KeyType = "private"
	Public  KeyType = "public"
)

// CryptoKey represents a cryptographic key obtained from one of the SubtleCrypto
// methods GenerateKey(), DeriveKey(), ImportKey(), or UnwrapKey().
// See §13. (https://w3c.github.io/webcrypto/#cryptokey-interface).
type CryptoKey interface {
	// Type refers to the type of key the object represents. It may take one of the following values:
	// "secret", "private" or "public".
	Type() KeyType

	// A boolean value indicating whether or not the key may be extracted
	// using SubtleCrypto.ExportKey() or SubtleCrypto.WrapKey().
	Extractable() bool

	// An object describing the algorithm for which this key can be used and any associated extra parameters.
	Algorithm() KeyAlgorithm

	// An Array of strings, indicating what can be done with the key. Possible values for array
	// elements are "encrypt", "decrypt", "sign", "verify", "deriveKey", "deriveBits", "wrapKey",
	// and "unwrapKey".
	Usages() []KeyUsage
}

// CryptoKeyPair represents an asymmetric key pair that is comprised of both public (PublicKey)
// and private (PrivateKey) keys.
// See §17. (https://w3c.github.io/webcrypto/#keypair)
type CryptoKeyPair interface {
	PrivateKey() CryptoKey
	PublicKey() CryptoKey
}
