// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import "errors"

// ErrIncorrectType is returned when the type supplied to the checker is not correct.
var ErrIncorrectType = errors.New("incorrect type supplied to checker")
