// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
)

// NameFromResourceID returns the name of the resource from a resource ID.
func NameFromResourceID(resID string) (string, error) {
	r, err := arm.ParseResourceID(resID)
	if err != nil {
		return "", fmt.Errorf("assets.NameFromResourceId: could not parse %s: %w", resID, err)
	}

	return r.Name, nil
}

// ResourceTypeFromResourceID returns the resource type of the resource from a resource ID.
func ResourceTypeFromResourceID(resID string) (string, error) {
	r, err := arm.ParseResourceID(resID)
	if err != nil {
		return "", fmt.Errorf("assets.ResourceTypeFromResourceId: could not parse %s: %w", resID, err)
	}

	return r.ResourceType.Type, nil
}
