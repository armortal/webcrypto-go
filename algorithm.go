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
