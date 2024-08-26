// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
)

// NameFromResourceId returns the name of the resource from a resource ID.
func NameFromResourceId(resId string) (string, error) {
	r, err := arm.ParseResourceID(resId)
	if err != nil {
		return "", fmt.Errorf("assets.NameFromResourceId: could not parse %s: %w", resId, err)
	}
	return r.Name, nil
}

// ResourceTypeFromResourceId returns the resource type of the resource from a resource ID.
func ResourceTypeFromResourceId(resId string) (string, error) {
	r, err := arm.ParseResourceID(resId)
	if err != nil {
		return "", fmt.Errorf("assets.ResourceTypeFromResourceId: could not parse %s: %w", resId, err)
	}
	return r.ResourceType.Type, nil
}
