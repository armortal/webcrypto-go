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
	"github.com/armortal/webcrypto-go"
)

// CheckUsages will check if the usages provided are valid usages in the allowed array.
func AreUsagesValid(allowed []webcrypto.KeyUsage, usages []webcrypto.KeyUsage) bool {
loop:
	for _, x := range usages {
		for _, y := range allowed {
			if x == y {
				continue loop
			}
		}
		return false
	}
	return true
}
