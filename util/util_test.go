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

package util

import (
	"testing"

	"github.com/armortal/webcrypto-go"
)

func TestUsageIntersection(t *testing.T) {
	res := UsageIntersection([]webcrypto.KeyUsage{
		webcrypto.Encrypt,
		webcrypto.WrapKey,
	}, []webcrypto.KeyUsage{webcrypto.Encrypt})

	if len(res) != 1 {
		t.Fatal("only one usage should have been returned")
	}

	if res[0] != webcrypto.Encrypt {
		t.Fatal("encrypt should have been included")
	}

	res = UsageIntersection([]webcrypto.KeyUsage{
		webcrypto.Encrypt,
		webcrypto.WrapKey,
	}, []webcrypto.KeyUsage{})

	if len(res) != 0 {
		t.Fatal("no values should have been returned")
	}
}
