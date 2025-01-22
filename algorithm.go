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

import "fmt"

var algorithms = map[string]SubtleCrypto{}

// Algorithm implements the Algorithm dictionary type as specified at
// §11 https://www.w3.org/TR/WebCryptoAPI/#algorithm-dictionary.
//
// The WebCrypto spec has specific algorithm params extend Algorithm however in Go
// it can be messy when 'extending' structs so we keep it simple here by
// having specific algorithm params set in the Params field. This keeps things
// consistent and simple.
type Algorithm struct {
	Name   string
	Params any
}

// KeyAlgorithm implements the KeyAlgorithm dictionary type as specified at
// §12 https://www.w3.org/TR/WebCryptoAPI/#dfn-KeyAlgorithm.
//
// We use an interface here because this is the algorithm that is part of a
// CryptoKey and we don't want the values changed.
type KeyAlgorithm interface {
	Name() string
}

// RegisterAlgorithm will register SubtleCrypto implementations referenced by the algorithm
// name provided. When fn gets called, it should return a NEW instance of the implementation.
func RegisterAlgorithm(name string, subtle SubtleCrypto) {
	_, ok := algorithms[name]
	if ok {
		panic(fmt.Sprintf("%s algorithm already registered", name))
	}
	algorithms[name] = subtle
}

func getSubtleCrypto(name string) (SubtleCrypto, error) {
	subtle, ok := algorithms[name]
	if !ok {
		return nil, NewError(ErrNotSupportedError, "algorithm not registered")
	}
	return subtle, nil
}
