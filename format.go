package webcrypto

type KeyFormat string

const (
	Raw                  KeyFormat = "raw"   // Raw format.
	PKCS8                KeyFormat = "pkcs8" // PKCS #8 format.
	SubjectPublicKeyInfo KeyFormat = "spki"  // SubjectPublicKeyInfo format.
	Jwk                  KeyFormat = "jwk"   // JSON Web Key format.
)

type RsaOtherPrimesInfo struct {
	// The following fields are defined in Section 6.3.2.7 of JSON Web Algorithms
	R string `json:"r,omitempty"`
	D string `json:"d,omitempty"`
	T string `json:"t,omitempty"`
}

type JsonWebKey struct {
	// The following fields are defined in Section 3.1 of JSON Web Key
	Kty    string     `json:"kty,omitempty"`
	Use    string     `json:"use,omitempty"`
	KeyOps []KeyUsage `json:"key_ops,omitempty"`
	Alg    string     `json:"alg,omitempty"`

	// The following fields are defined in JSON Web Key Parameters Registration
	Ext bool `json:"ext,omitempty"`

	// The following fields are defined in Section 6 of JSON Web Algorithms
	Crv string               `json:"crv,omitempty"`
	X   string               `json:"x,omitempty"`
	Y   string               `json:"y,omitempty"`
	D   string               `json:"d,omitempty"`
	N   string               `json:"n,omitempty"`
	E   string               `json:"e,omitempty"`
	P   string               `json:"p,omitempty"`
	Q   string               `json:"q,omitempty"`
	Dp  string               `json:"dp,omitempty"`
	Dq  string               `json:"dq,omitempty"`
	Qi  string               `json:"qi,omitempty"`
	Oth []RsaOtherPrimesInfo `json:"oth,omitempty"`
	K   string               `json:"k,omitempty"`
}
