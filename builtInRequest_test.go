// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltInRequestString(t *testing.T) {
	t.Parallel()

	t.Run("with version", func(t *testing.T) {
		t.Parallel()

		resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/testPolicy")
		require.NoError(t, err)

		req := BuiltInRequest{
			ResourceID: resID,
			Version:    to.Ptr("1.0.0"),
		}

		expected := "/providers/Microsoft.Authorization/policyDefinitions/testPolicy@1.0.0"
		assert.Equal(t, expected, req.String())
	})

	t.Run("without version", func(t *testing.T) {
		t.Parallel()

		resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policyDefinitions/testPolicy")
		require.NoError(t, err)

		req := BuiltInRequest{
			ResourceID: resID,
			Version:    nil,
		}

		expected := "/providers/Microsoft.Authorization/policyDefinitions/testPolicy"
		assert.Equal(t, expected, req.String())
	})

	t.Run("with policy set definition", func(t *testing.T) {
		t.Parallel()

		resID, err := arm.ParseResourceID("/providers/Microsoft.Authorization/policySetDefinitions/testPolicySet")
		require.NoError(t, err)

		req := BuiltInRequest{
			ResourceID: resID,
			Version:    to.Ptr("2.1.3"),
		}

		expected := "/providers/Microsoft.Authorization/policySetDefinitions/testPolicySet@2.1.3"
		assert.Equal(t, expected, req.String())
	})
}

func TestJoinNameAndVersion(t *testing.T) {
	t.Parallel()

	t.Run("with version", func(t *testing.T) {
		t.Parallel()

		result := JoinNameAndVersion("testName", to.Ptr("1.0.0"))
		assert.Equal(t, "testName@1.0.0", result)
	})

	t.Run("without version", func(t *testing.T) {
		t.Parallel()

		result := JoinNameAndVersion("testName", nil)
		assert.Equal(t, "testName", result)
	})
}
