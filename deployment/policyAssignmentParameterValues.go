// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

// PolicyAssignmentsParameterValues is a map of policy assignments names toa map of policy parameter names to parameter values.
type PolicyAssignmentsParameterValues map[string]map[string]*armpolicy.ParameterValuesValue
