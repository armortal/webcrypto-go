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

import (
	"errors"
	"fmt"
)

const (
	ErrDataError          string = "DataError"
	ErrInvalidAccessError string = "InvalidAccessError"
	ErrNotSupportedError  string = "NotSupportedError"
	ErrOperationError     string = "OperationError"
	ErrQuotaExceededError string = "QuotaExceededError"
	ErrSyntaxError        string = "SyntaxError"
)

type Error interface {
	error

	Name() string

	Message() string
}

func NewError(name string, message string) Error {
	return &errorInternal{
		name:    name,
		message: message,
	}
}

func FromError(err error) (Error, error) {
	e, ok := err.(*errorInternal)
	if !ok {
		return nil, errors.New("error is not *webcrypto.Error")
	}
	return e, nil
}

type errorInternal struct {
	name    string
	message string
}

func (e *errorInternal) Error() string {
	return fmt.Sprintf("webcrypto: %s: %s", e.name, e.message)
}

func (e *errorInternal) Name() string {
	return e.name
}

func (e *errorInternal) Message() string {
	return e.message
}

// ErrMethodNotSupported helper function that returns an ErrNotSupportedError.
func ErrMethodNotSupported() Error {
	return NewError(ErrNotSupportedError, "method not supported")
}

// ErrInvalidUsages helper function that returns a ErrSyntaxError for invalid usages.
func ErrInvalidUsages(allowed ...KeyUsage) Error {
	usages := ""
	for _, v := range allowed {
		if usages == "" {
			usages = string(v)
			continue
		}
		usages = fmt.Sprintf("%s,%s", usages, v)
	}
	return NewError(ErrSyntaxError, fmt.Sprintf("[%s] are the only valid usages", usages))
}
