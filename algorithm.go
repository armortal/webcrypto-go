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

var algorithms = map[string]func() SubtleCrypto{}

// Algorithm implements the Algorithm dictionary type as specified at
// §11 https://www.w3.org/TR/WebCryptoAPI/#algorithm-dictionary.
// We use an interface here because when passing an algorithm to subtle crypto, it can be
// multiple different param types depending on the algorithm name.
type Algorithm interface {
	GetName() string
}

// KeyAlgorithm implements the KeyAlgorithm dictionary type as specified at
// §12 https://www.w3.org/TR/WebCryptoAPI/#dfn-KeyAlgorithm.
type KeyAlgorithm interface {
	GetName() string
}

// RegisterAlgorithm will register SubtleCrypto implementations referenced by the algorithm
// name provided. When fn gets called, it should return a NEW instance of the implementation.
func RegisterAlgorithm(name string, fn func() SubtleCrypto) {
	algorithms[name] = fn
}

func getSubtleCrypto(alg Algorithm) (func() SubtleCrypto, error) {
	subtle, ok := algorithms[alg.GetName()]
	if !ok {
		return nil, NewError(ErrNotSupportedError, "algorithm not registered")
	}
	return subtle, nil
}
