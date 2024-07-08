// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import mapset "github.com/deckarep/golang-set/v2"

// PolicyAssignmentsParameterValues is a map of default names to DefaultPolicyAssignmentValuesValue.
// It is used to map a single value to multiple policy assignments.
type DefaultPolicyAssignmentValues map[string]DefaultPolicyAssignmentValuesValue

// DefaultPolicyAssignmentValuesValue is a map of assignments names to parameter names.
type DefaultPolicyAssignmentValuesValue map[string]mapset.Set[string]
