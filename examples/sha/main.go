package main

import (
	"encoding/hex"
	"fmt"

	"github.com/armortal/webcrypto-go"
	"github.com/armortal/webcrypto-go/algorithms/sha"
)

func main() {
	// digest something
	hash, err := webcrypto.Subtle().Digest(
		&webcrypto.Algorithm{
			Name:   "SHA-256",
			Params: &sha.Params{}, // we use *sha.Params so we can register the algorithm without using a blank import
		}, []byte("test"))

	if err != nil {
		panic(err)
	}

	// do something with hash
	fmt.Println(hex.EncodeToString(hash))
}
