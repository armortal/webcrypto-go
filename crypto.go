// Copyright 2023-2025 ARMORTAL TECHNOLOGIES PTY LTD

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package webcrypto implements the WebCrypto API specification (https://www.w3.org/TR/WebCryptoAPI/).
package webcrypto

import (
	"crypto/rand"

	"github.com/google/uuid"
)

// GetRandomValues generates cryptographically strong random values.
// See §10.1.1 (https://w3c.github.io/webcrypto/#Crypto-method-getRandomValues)
func GetRandomValues(b []byte) error {
	if len(b) > 65536 {
		return NewError(ErrQuotaExceededError, "byte array length greater than 65536")
	}
	_, err := rand.Read(b)
	return err
}

// RandomUUID generates a new version 4 UUID and returns its namespace specific string representation
// as described in section 3 of [RFC4122].
// See §10.1.2 (https://w3c.github.io/webcrypto/#Crypto-method-randomUUID)
func RandomUUID() string {
	return uuid.NewString()
}
