// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"testing"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalJson(t *testing.T) {
	data := []byte(`{"name": "John", "age": 30}`)
	ext := ".json"
	u := NewUnmarshaler(data, ext)

	var dst map[string]interface{}

	err := u.Unmarshal(&dst)

	require.NoError(t, err)
	assert.Equal(t, "John", dst["name"])
	assert.InEpsilon(t, float64(30), dst["age"], 0.01)
}

func TestUnmarshalYaml(t *testing.T) {
	data := []byte(`
name: John
age: 30
`)
	for _, ext := range []string{".yaml", ".yml"} {
		u := NewUnmarshaler(data, ext)

		var dst map[string]interface{}

		err := u.Unmarshal(&dst)

		require.NoError(t, err)
		assert.Equal(t, "John", dst["name"])
		// YAML is routed through JSON so that `json` struct tags and json.Unmarshaler
		// implementations are honoured. A side effect is that numbers decoded into an
		// untyped destination arrive as float64 rather than int, matching the JSON path
		// exactly. Typed destinations are unaffected.
		assert.InEpsilon(t, float64(30), dst["age"], 0.01)
	}
}

// TestUnmarshalYamlJsonParity asserts the property the fix is really about: equivalent
// YAML and JSON documents must produce identical results.
func TestUnmarshalYamlJsonParity(t *testing.T) {
	yamlData := []byte("name: John\nage: 30\nnested:\n  values:\n    - 1\n    - 2\n")
	jsonData := []byte(`{"name":"John","age":30,"nested":{"values":[1,2]}}`)

	var fromYAML, fromJSON map[string]interface{}

	require.NoError(t, NewUnmarshaler(yamlData, ".yaml").Unmarshal(&fromYAML))
	require.NoError(t, NewUnmarshaler(jsonData, ".json").Unmarshal(&fromJSON))

	assert.Equal(t, fromJSON, fromYAML)
}

// TestUnmarshalYamlNonStringKeys covers the normalizeYAMLToJSON helper. yaml.v3 decodes a
// mapping with non-string keys into map[interface{}]interface{}, which encoding/json
// cannot marshal; the helper converts those keys the way JSON would represent them.
func TestUnmarshalYamlNonStringKeys(t *testing.T) {
	data := []byte("1: one\n2: two\n")

	var dst map[string]interface{}

	require.NoError(t, NewUnmarshaler(data, ".yaml").Unmarshal(&dst))
	assert.Equal(t, "one", dst["1"])
	assert.Equal(t, "two", dst["2"])
}

// The tests below unmarshal into typed structs rather than map[string]interface{}.
// Struct tags are irrelevant when the destination is a map, which is why the existing
// tests above passed while YAML parsing of typed assets was broken.

// TestUnmarshalYamlIntoTypedStructRoleDefinition covers issue #4225: a YAML role
// definition using the documented camelCase keys must populate the typed struct
// identically to its JSON equivalent.
func TestUnmarshalYamlIntoTypedStructRoleDefinition(t *testing.T) {
	yamlData := []byte(`
name: 00000000-0000-0000-0000-000000000001
type: Microsoft.Authorization/roleDefinitions
properties:
  roleName: Test-Role-Definition
  description: A test role definition.
  assignableScopes:
    - /providers/Microsoft.Management/managementGroups/placeholder
  permissions:
    - actions:
        - Microsoft.Resources/subscriptions/resourceGroups/read
      notActions: []
`)

	jsonData := []byte(`{
  "name": "00000000-0000-0000-0000-000000000001",
  "type": "Microsoft.Authorization/roleDefinitions",
  "properties": {
    "roleName": "Test-Role-Definition",
    "description": "A test role definition.",
    "assignableScopes": [
      "/providers/Microsoft.Management/managementGroups/placeholder"
    ],
    "permissions": [
      {
        "actions": [
          "Microsoft.Resources/subscriptions/resourceGroups/read"
        ],
        "notActions": []
      }
    ]
  }
}`)

	for _, ext := range []string{".yaml", ".yml"} {
		t.Run(ext, func(t *testing.T) {
			rd := new(assets.RoleDefinition)
			err := NewUnmarshaler(yamlData, ext).Unmarshal(rd)
			require.NoError(t, err)
			require.NotNil(t, rd.Properties)
			require.NotNil(t, rd.Properties.RoleName)
			assert.Equal(t, "Test-Role-Definition", *rd.Properties.RoleName)
			require.NotNil(t, rd.Name)
			assert.Equal(t, "00000000-0000-0000-0000-000000000001", *rd.Name)
			require.Len(t, rd.Properties.AssignableScopes, 1)
			assert.Equal(
				t,
				"/providers/Microsoft.Management/managementGroups/placeholder",
				*rd.Properties.AssignableScopes[0],
			)
			require.Len(t, rd.Properties.Permissions, 1)
			require.Len(t, rd.Properties.Permissions[0].Actions, 1)
		})
	}

	// The YAML result must be indistinguishable from the JSON result.
	t.Run("parity with json", func(t *testing.T) {
		fromYAML := new(assets.RoleDefinition)
		require.NoError(t, NewUnmarshaler(yamlData, ".yaml").Unmarshal(fromYAML))

		fromJSON := new(assets.RoleDefinition)
		require.NoError(t, NewUnmarshaler(jsonData, ".json").Unmarshal(fromJSON))

		assert.Equal(t, fromJSON, fromYAML)
	})
}

// TestUnmarshalYamlIntoTypedStructPolicyDefinition covers the policy definition asset
// type, which shares the same unmarshaler and previously had no YAML test coverage.
func TestUnmarshalYamlIntoTypedStructPolicyDefinition(t *testing.T) {
	yamlData := []byte(`
name: test-policy-definition
type: Microsoft.Authorization/policyDefinitions
properties:
  displayName: Test Policy Definition
  description: A test policy definition.
  mode: All
  policyType: Custom
  metadata:
    category: Testing
    version: 1.0.0
  parameters:
    effect:
      type: String
      defaultValue: Audit
      allowedValues:
        - Audit
        - Deny
        - Disabled
  policyRule:
    if:
      field: type
      equals: Microsoft.Storage/storageAccounts
    then:
      effect: "[parameters('effect')]"
`)

	pd := new(assets.PolicyDefinition)
	require.NoError(t, NewUnmarshaler(yamlData, ".yaml").Unmarshal(pd))
	require.NotNil(t, pd.Name)
	assert.Equal(t, "test-policy-definition", *pd.Name)
	require.NotNil(t, pd.Properties)
	require.NotNil(t, pd.Properties.DisplayName)
	assert.Equal(t, "Test Policy Definition", *pd.Properties.DisplayName)
	require.NotNil(t, pd.Properties.PolicyType)
	assert.Equal(t, armpolicy.PolicyTypeCustom, *pd.Properties.PolicyType)
	assert.Contains(t, pd.Properties.Parameters, "effect")
	assert.NotNil(t, pd.Properties.PolicyRule)
}

// TestUnmarshalYamlIntoTypedStructPolicySetDefinition covers the policy set definition
// asset type, which shares the same unmarshaler and previously had no YAML coverage.
func TestUnmarshalYamlIntoTypedStructPolicySetDefinition(t *testing.T) {
	yamlData := []byte(`
name: test-policy-set-definition
type: Microsoft.Authorization/policySetDefinitions
properties:
  displayName: Test Policy Set Definition
  description: A test policy set definition.
  policyType: Custom
  policyDefinitions:
    - policyDefinitionReferenceId: TestRef
      policyDefinitionId: /providers/Microsoft.Management/managementGroups/placeholder/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition
      parameters:
        effect:
          value: "[parameters('effect')]"
  parameters:
    effect:
      type: String
      defaultValue: Audit
`)

	psd := new(assets.PolicySetDefinition)
	require.NoError(t, NewUnmarshaler(yamlData, ".yaml").Unmarshal(psd))
	require.NotNil(t, psd.Name)
	assert.Equal(t, "test-policy-set-definition", *psd.Name)
	require.NotNil(t, psd.Properties)
	require.NotNil(t, psd.Properties.DisplayName)
	assert.Equal(t, "Test Policy Set Definition", *psd.Properties.DisplayName)
	require.Len(t, psd.Properties.PolicyDefinitions, 1)
	require.NotNil(t, psd.Properties.PolicyDefinitions[0].PolicyDefinitionReferenceID)
	assert.Equal(t, "TestRef", *psd.Properties.PolicyDefinitions[0].PolicyDefinitionReferenceID)
}

// TestUnmarshalYamlIntoTypedStructPolicyAssignment covers the policy assignment asset
// type, which shares the same unmarshaler and previously had no YAML coverage.
func TestUnmarshalYamlIntoTypedStructPolicyAssignment(t *testing.T) {
	yamlData := []byte(`
name: test-policy-assignment
type: Microsoft.Authorization/policyAssignments
properties:
  displayName: Test Policy Assignment
  description: A test policy assignment.
  policyDefinitionId: /providers/Microsoft.Management/managementGroups/placeholder/providers/Microsoft.Authorization/policySetDefinitions/test-policy-set-definition
  enforcementMode: Default
  parameters:
    effect:
      value: Audit
`)

	pa := new(assets.PolicyAssignment)
	require.NoError(t, NewUnmarshaler(yamlData, ".yaml").Unmarshal(pa))
	require.NotNil(t, pa.Name)
	assert.Equal(t, "test-policy-assignment", *pa.Name)
	require.NotNil(t, pa.Properties)
	require.NotNil(t, pa.Properties.DisplayName)
	assert.Equal(t, "Test Policy Assignment", *pa.Properties.DisplayName)
	require.NotNil(t, pa.Properties.PolicyDefinitionID)
	assert.Contains(t, *pa.Properties.PolicyDefinitionID, "test-policy-set-definition")
	assert.Contains(t, pa.Properties.Parameters, "effect")
}
