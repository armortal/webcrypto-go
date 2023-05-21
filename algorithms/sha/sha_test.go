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

package sha

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSHA1(t *testing.T) {
	input := "helloworld"
	output := "6adfb183a4a2c94a2f92dab5ade762a47889a5a1"

	subtle := &subtleCrypto{
		name: sha_1,
	}
	digest(t, input, subtle, output)
	digestMismatch(t, input, subtle, "some-invalid-output")
}

func TestSHA256(t *testing.T) {
	input := "helloworld"
	output := "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
	subtle := &subtleCrypto{
		name: sha_256,
	}
	digest(t, input, subtle, output)
	digestMismatch(t, input, subtle, "some-invalid-output")
}

func TestSHA384(t *testing.T) {
	input := "helloworld"
	output := "97982a5b1414b9078103a1c008c4e3526c27b41cdbcf80790560a40f2a9bf2ed4427ab1428789915ed4b3dc07c454bd9"
	subtle := &subtleCrypto{
		name: sha_384,
	}
	digest(t, input, subtle, output)
	digestMismatch(t, input, subtle, "some-invalid-output")
}

func TestSHA512(t *testing.T) {
	input := "helloworld"
	output := "1594244d52f2d8c12b142bb61f47bc2eaf503d6d9ca8480cae9fcf112f66e4967dc5e8fa98285e36db8af1b8ffa8b84cb15e0fbcf836c3deb803c13f37659a60"
	subtle := &subtleCrypto{
		name: sha_512,
	}
	digest(t, input, subtle, output)
	digestMismatch(t, input, subtle, "some-invalid-output")
}

func digestMismatch(t *testing.T, input string, subtle *subtleCrypto, output string) {
	act, err := subtle.Digest(&Algorithm{Name: subtle.name}, bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", act) == output {
		t.Fatal("digest should have mismatched")
	}
}

func digest(t *testing.T, input string, subtle *subtleCrypto, exp string) {
	act, err := subtle.Digest(&Algorithm{Name: subtle.name}, bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatal(err)
	}

	if fmt.Sprintf("%x", act) != exp {
		t.Fatal("digest mismatch")
	}
}
