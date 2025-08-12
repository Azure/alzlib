// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package checks

import "errors"

// ErrIncorrectType is returned when the type supplied to the checker is not correct.
var ErrIncorrectType = errors.New("incorrect type supplied to checker")
