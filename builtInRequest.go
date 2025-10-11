// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"

// BuiltInRequest contains the values required to retrieve a policy (set) definition from Azure.
type BuiltInRequest struct {
	ResourceID *arm.ResourceID
	Version    *string
}

// String returns a string representation of the BuiltInRequest in the format "resourceID@version".
// If the Version is nil, it returns just the resourceID.
func (b BuiltInRequest) String() string {
	if b.Version != nil {
		return b.ResourceID.String() + "@" + *b.Version
	}

	return b.ResourceID.String()
}
