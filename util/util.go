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

// Package util contains utility functions.
package util

import "github.com/armortal/webcrypto-go"

// AreUsagesValid will check if the usages provided exist in the usages allowed.
func AreUsagesValid(allowed []webcrypto.KeyUsage, actual []webcrypto.KeyUsage) error {
	if len(actual) == 0 && len(allowed) > 0 {
		return webcrypto.ErrInvalidUsages(allowed...)
	}
loop:
	for _, x := range actual {
		for _, y := range allowed {
			if x == y {
				continue loop
			}
		}
		return webcrypto.ErrInvalidUsages(allowed...)
	}
	return nil
}

// UsageIntersection returns the intersection of v1 and v2 values.
func UsageIntersection(v1 []webcrypto.KeyUsage, v2 []webcrypto.KeyUsage) []webcrypto.KeyUsage {
	i := make([]webcrypto.KeyUsage, 0)
	for _, x := range v1 {
		for _, y := range v2 {
			if x == y {
				i = append(i, x)
			}
		}
	}
	return i
}
