// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package processor

import (
	"bytes"
	"os"
	"regexp"
	"testing"
	"text/template"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFullLibrary.
func TestFullLibrary(t *testing.T) {
	t.Parallel()

	fs := os.DirFS("./testdata")
	pc := NewClient(fs)
	res := NewResult()
	require.NoError(t, pc.Process(res))
	assert.Equal(t, 13, res.LibArchetypes["root"].PolicyAssignments.Cardinality())
	assert.Equal(t, 114, res.LibArchetypes["root"].PolicyDefinitions.Cardinality())
	assert.Equal(t, 12, res.LibArchetypes["root"].PolicySetDefinitions.Cardinality())
	assert.Equal(t, 5, res.LibArchetypes["root"].RoleDefinitions.Cardinality())
	assert.Len(t, res.LibArchetypeOverrides, 1)
	assert.Len(t, res.LibDefaultPolicyValues, 1)
	assert.Len(t, res.LibArchitectures["alz"].ManagementGroups, 9)
	assert.Equal(t, "test", res.Metadata.Name)
	assert.Equal(t, "test display name.", res.Metadata.DisplayName)
	assert.Equal(t, "test description", res.Metadata.Description)
	assert.Equal(t, []LibMetadataDependency{
		{
			Path: "platform/test",
			Ref:  "2024.08.0",
		},
		{
			CustomURL: "../testdir",
		},
	}, res.Metadata.Dependencies)
}

func TestYamlDecode(t *testing.T) {
	t.Parallel()

	fs := os.DirFS("./yamllib")
	pc := NewClient(fs)
	res := NewResult()
	require.NoError(t, pc.Process(res))
	assert.Len(t, res.PolicyAssignments, 1)
	assert.Len(t, res.LibArchetypes, 1)
	assert.Len(t, res.LibArchitectures, 1)
}

// TestProcessArchetypeOverrideValid tests the processing of a valid archetype override.
func TestProcessArchetypeOverrideValid(t *testing.T) {
	t.Parallel()

	sampleData := getSampleArchetypeOverride_valid()
	res := &Result{
		LibArchetypeOverrides: make(map[string]*LibArchetypeOverride, 0),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	require.NoError(t, processArchetypeOverride(res, unmar))
	assert.Len(t, res.LibArchetypeOverrides, 1)
	assert.Equal(t, 1, res.LibArchetypeOverrides["test"].PolicyAssignmentsToAdd.Cardinality())
	assert.Equal(t, 1, res.LibArchetypeOverrides["test"].PolicyAssignmentsToRemove.Cardinality())
	assert.Equal(t, 1, res.LibArchetypeOverrides["test"].PolicyDefinitionsToAdd.Cardinality())
	assert.Equal(t, 1, res.LibArchetypeOverrides["test"].PolicyDefinitionsToRemove.Cardinality())
}

// TestProcessArchetypeOverrideInvalid tests the processing of a valid archetype override.
func TestProcessArchetypeOverrideInvalid(t *testing.T) {
	t.Parallel()

	sampleData := getSampleArchetypeOverride_invalid()
	res := &Result{
		LibArchetypeOverrides: make(map[string]*LibArchetypeOverride, 0),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	err := processArchetypeOverride(res, unmar)
	assert.ErrorContains(t, err, "invalid character ']' after object key:value pair")
}

// TestProcessArchetypeDefinitionValid test the processing of a valid archetype definition.
func TestProcessArchetypeDefinitionValid(t *testing.T) {
	t.Parallel()

	sampleData := getSampleArchetypeDefinition_valid()
	res := &Result{
		LibArchetypes: make(map[string]*LibArchetype, 0),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	require.NoError(t, processArchetype(res, unmar))
	assert.Len(t, res.LibArchetypes, 1)
	assert.Equal(t, 1, res.LibArchetypes["test"].PolicyAssignments.Cardinality())
	assert.Equal(t, 1, res.LibArchetypes["test"].PolicyDefinitions.Cardinality())
	assert.Equal(t, 1, res.LibArchetypes["test"].PolicySetDefinitions.Cardinality())
	assert.Equal(t, 1, res.LibArchetypes["test"].RoleDefinitions.Cardinality())
}

// TestProcessArchetypeDefinition_multipleTopLevelObjects tests that the correct error
// is generated when there as JSON errors in the archetype definition.
func Test_processArchetypeDefinition_invalidJson(t *testing.T) {
	t.Parallel()

	sampleData := getSampleArchetypeDefinition_invalidJson()
	res := &Result{
		LibArchetypes: make(map[string]*LibArchetype, 0),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	assert.ErrorContains(t, processArchetype(res, unmar), "invalid character '[' after object key")
}

// TestProcessPolicyAssignmentValid tests the processing of a valid policy assignment.
func TestProcessPolicyAssignmentValid(t *testing.T) {
	t.Parallel()

	sampleData := getSamplePolicyAssignment()
	res := &Result{
		PolicyAssignments: make(map[string]*assets.PolicyAssignment),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	require.NoError(t, processPolicyAssignment(res, unmar))
	assert.Len(t, res.PolicyAssignments, 1)
	assert.Equal(t, "Deny-Storage-http", *res.PolicyAssignments["Deny-Storage-http"].Name)
	assert.Equal(
		t,
		"Secure transfer to storage accounts should be enabled",
		*res.PolicyAssignments["Deny-Storage-http"].Properties.DisplayName,
	)
}

// TestProcessPolicyAssignmentNoName tests that the processing of a assignment
// with a missing name field throws the correct error.
func TestProcessPolicyAssignmentNoName(t *testing.T) {
	t.Parallel()

	sampleData := getSamplePolicyAssignment_noName()
	res := &Result{
		PolicyAssignments: make(map[string]*assets.PolicyAssignment),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	assert.ErrorContains(t, processPolicyAssignment(res, unmar), "name must not be nil")
}

// TestProcessPolicyDefinitionValid tests the processing of a valid policy definition.
func TestProcessPolicyDefinitionValid(t *testing.T) {
	t.Parallel()

	sampleData := getSamplePolicyDefinition()
	res := &Result{
		PolicyDefinitions: make(map[string]*armpolicy.Definition),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	require.NoError(t, processPolicyDefinition(res, unmar))
	assert.Len(t, res.PolicyDefinitions, 1)
	assert.Equal(
		t,
		"Append-AppService-httpsonly",
		*res.PolicyDefinitions["Append-AppService-httpsonly"].Name,
	)
	assert.Equal(
		t,
		armpolicy.PolicyTypeCustom,
		*res.PolicyDefinitions["Append-AppService-httpsonly"].Properties.PolicyType,
	)
}

// TestProcessPolicyDefinitionNoName tests that the processing of a definition
// with a missing name field throws the correct error.
func TestProcessPolicyDefinitionNoName(t *testing.T) {
	t.Parallel()

	sampleData := getSamplePolicyDefinition_noName()
	res := &Result{
		PolicyDefinitions: make(map[string]*armpolicy.Definition),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	assert.ErrorIs(
		t,
		processPolicyDefinition(res, unmar),
		ErrNoNameProvided,
	)
}

// TestProcessSetPolicyDefinitionValid tests the processing of a valid policy set definition.
func TestProcessSetPolicyDefinitionValid(t *testing.T) {
	t.Parallel()

	sampleData := getSamplePolicySetDefinition()
	res := &Result{
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	require.NoError(t, processPolicySetDefinition(res, unmar))
	assert.Len(t, res.PolicySetDefinitions, 1)
	assert.Equal(t, "Deploy-MDFC-Config", *res.PolicySetDefinitions["Deploy-MDFC-Config"].Name)
	assert.Equal(
		t,
		armpolicy.PolicyTypeCustom,
		*res.PolicySetDefinitions["Deploy-MDFC-Config"].Properties.PolicyType,
	)
}

// TestProcessPolicySetDefinitionNoName tests that the processing of a set definition
// with a missing name field throws the correct error.
func TestProcessPolicySetDefinitionNoName(t *testing.T) {
	t.Parallel()

	sampleData := getSamplePolicySetDefinition_noName()
	res := &Result{
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	assert.ErrorIs(
		t,
		processPolicySetDefinition(res, unmar),
		ErrNoNameProvided,
	)
}

// TestProcessPolicyAssignmentNoData tests the processing of an invalid policy assignment with no
// data.
func TestProcessPolicyAssignmentNoData(t *testing.T) {
	t.Parallel()

	res := &Result{}
	unmar := newUnmarshaler([]byte{}, ".json")
	assert.ErrorContains(t, processPolicyAssignment(res, unmar), "unexpected end of JSON input")
}

// TestProcessPolicyDefinitionNoData tests the processing of an invalid policy definition with no
// data.
func TestProcessPolicyDefinitionNoData(t *testing.T) {
	t.Parallel()

	res := &Result{}
	unmar := newUnmarshaler([]byte{}, ".json")
	assert.ErrorContains(t, processPolicyDefinition(res, unmar), "unexpected end of JSON input")
}

// TestProcessSetPolicyDefinitionNoData tests the processing of an invalid policy set definition
// with no data.
func TestProcessPolicySetDefinitionNoData(t *testing.T) {
	t.Parallel()

	res := &Result{}
	unmar := newUnmarshaler([]byte{}, ".json")
	assert.ErrorContains(t, processPolicySetDefinition(res, unmar), "unexpected end of JSON input")
}

// TestProcessRoleDefinitionWithDataActions tests the processing of a role definition with data
// actions.
func TestProcessRoleDefinitionWithDataActions(t *testing.T) {
	t.Parallel()

	sampleData := getSampleRoleDefinitionWithDataActions()
	res := &Result{
		RoleDefinitions: make(map[string]*armauthorization.RoleDefinition),
	}
	unmar := newUnmarshaler(sampleData, ".json")
	require.NoError(t, processRoleDefinition(res, unmar))
	assert.Len(t, res.RoleDefinitions, 1)
	assert.Equal(
		t,
		"86e16db7-c2fd-4674-b263-8ca9eef74d85",
		*res.RoleDefinitions["test-role-definition"].Name,
	)
	assert.Equal(
		t,
		"test-role-definition",
		*res.RoleDefinitions["test-role-definition"].Properties.RoleName,
	)
	require.Len(t, res.RoleDefinitions["test-role-definition"].Properties.Permissions, 1)
	assert.Len(t, res.RoleDefinitions["test-role-definition"].Properties.Permissions[0].Actions, 4)
	assert.Len(
		t,
		res.RoleDefinitions["test-role-definition"].Properties.Permissions[0].DataActions,
		5,
	)
}

// getSampleRoleDefinitionWithDataActions returns a valid role definition with data actions.
// This is based on the storage blob data contributor role definition.
func getSampleRoleDefinitionWithDataActions() []byte {
	return []byte(`{
		"name": "86e16db7-c2fd-4674-b263-8ca9eef74d85",
		"type": "Microsoft.Authorization/roleDefinitions",
		"apiVersion": "2022-04-01",
    "roleType": "CustomRole",
		"properties": {
      "roleName": "test-role-definition",
      "description": "test role definition",
			"permissions": [
				{
					"actions": [
						"Microsoft.Storage/storageAccounts/blobServices/containers/delete",
						"Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/write",
            "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action"
					],
					"notActions": [],
					"dataActions": [
						"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
						"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"
					],
          "notDataActions": []
				}
			],
      "assignableScopes": [
        "/"
      ]
		}
	}`)
}

// getSampleArchetypeDefinition_valid returns a valid archetype definition.
func getSampleArchetypeDefinition_valid() []byte {
	return []byte(`{
	"name": "test",
	"policy_assignments": [
		"Deploy-ASC-Monitoring"
	],
	"policy_definitions": [
		"Append-AppService-httpsonly"
	],
	"policy_set_definitions": [
		"Deny-PublicPaaSEndpoints"
	],
	"role_definitions": [
		"Network-Subnet-Contributor"
	]
}
`)
}

// getSampleArchetypeDefinition_invalidJson returns an invalid JSON byte slice
// There is a missing colon after the policy_set_definitions key.
func getSampleArchetypeDefinition_invalidJson() []byte {
	return []byte(`{
		"es_root": {
			"policy_assignments": [],
			"policy_definitions": [],
			"policy_set_definitions" [],
			"role_definition": [],
			"archetype_config": {},
				"access_control": {}
			}
		}
	}`)
}

// getSamplePolicyAssignment returns a valid policy assignment as a byte slice.
func getSamplePolicyAssignment() []byte {
	return []byte(`{
		"name": "Deny-Storage-http",
		"type": "Microsoft.Authorization/policyAssignments",
		"apiVersion": "2019-09-01",
		"properties": {
			"description": "Audit requirement of Secure transfer in your storage account. Secure transfer is an option that forces your storage account to accept requests only from secure connections (HTTPS). Use of HTTPS ensures authentication between the server and the service and protects data in transit from network layer attacks such as man-in-the-middle, eavesdropping, and session-hijacking.",
			"displayName": "Secure transfer to storage accounts should be enabled",
			"notScopes": [],
			"parameters": {},
			"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9",
			"scope": "${current_scope_resource_id}",
			"enforcementMode": null
		},
		"location": "${default_location}",
		"identity": {
			"type": "None"
		}
	}`)
}

// getSamplePolicyAssignment_noName returns a policy assignment with no name as a byte slice
// the name field is missing, rather than empty.
func getSamplePolicyAssignment_noName() []byte {
	return []byte(`{
		"type": "Microsoft.Authorization/policyAssignments",
		"apiVersion": "2019-09-01",
		"properties": {
			"description": "Audit requirement of Secure transfer in your storage account. Secure transfer is an option that forces your storage account to accept requests only from secure connections (HTTPS). Use of HTTPS ensures authentication between the server and the service and protects data in transit from network layer attacks such as man-in-the-middle, eavesdropping, and session-hijacking.",
			"displayName": "Secure transfer to storage accounts should be enabled",
			"notScopes": [],
			"parameters": {},
			"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9",
			"scope": "${current_scope_resource_id}",
			"enforcementMode": null
		},
		"location": "${default_location}",
		"identity": {
			"type": "None"
		}
	}`)
}

// getSamplePolicyDefinition returns a valid policy definition as a byte slice.
func getSamplePolicyDefinition() []byte {
	return []byte(`{
		"name": "Append-AppService-httpsonly",
		"type": "Microsoft.Authorization/policyDefinitions",
		"apiVersion": "2021-06-01",
		"scope": null,
		"properties": {
			"policyType": "Custom",
			"mode": "All",
			"displayName": "AppService append enable https only setting to enforce https setting.",
			"description": "Appends the AppService sites object to ensure that  HTTPS only is enabled for  server/service authentication and protects data in transit from network layer eavesdropping attacks. Please note Append does not enforce compliance use then deny.",
			"metadata": {
				"version": "1.0.0",
				"category": "App Service"
			},
			"parameters": {
				"effect": {
					"type": "String",
					"defaultValue": "Append",
					"allowedValues": [
						"Append",
						"Disabled"
					],
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				}
			},
			"policyRule": {
				"if": {
					"allOf": [
						{
							"field": "type",
							"equals": "Microsoft.Web/sites"
						},
						{
							"field": "Microsoft.Web/sites/httpsOnly",
							"notequals": true
						}
					]
				},
				"then": {
					"effect": "[parameters('effect')]",
					"details": [
						{
							"field": "Microsoft.Web/sites/httpsOnly",
							"value": true
						}
					]
				}
			}
		}
	}`)
}

// getSamplePolicyDefinition_noName returns a policy definition with no name as a byte slice
// the name field is empty, rather than missing.
func getSamplePolicyDefinition_noName() []byte {
	return []byte(`{
		"name": "",
		"type": "Microsoft.Authorization/policyDefinitions",
		"apiVersion": "2021-06-01",
		"scope": null,
		"properties": {
			"policyType": "Custom",
			"mode": "All",
			"displayName": "AppService append enable https only setting to enforce https setting.",
			"description": "Appends the AppService sites object to ensure that  HTTPS only is enabled for  server/service authentication and protects data in transit from network layer eavesdropping attacks. Please note Append does not enforce compliance use then deny.",
			"metadata": {
				"version": "1.0.0",
				"category": "App Service"
			},
			"parameters": {
				"effect": {
					"type": "String",
					"defaultValue": "Append",
					"allowedValues": [
						"Append",
						"Disabled"
					],
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				}
			},
			"policyRule": {
				"if": {
					"allOf": [
						{
							"field": "type",
							"equals": "Microsoft.Web/sites"
						},
						{
							"field": "Microsoft.Web/sites/httpsOnly",
							"notequals": true
						}
					]
				},
				"then": {
					"effect": "[parameters('effect')]",
					"details": [
						{
							"field": "Microsoft.Web/sites/httpsOnly",
							"value": true
						}
					]
				}
			}
		}
	}`)
}

// getSamplePolicySetDefinition returns a valid policy set definition as a byte slice.
func getSamplePolicySetDefinition() []byte {
	return []byte(`{
		"name": "Deploy-MDFC-Config",
		"type": "Microsoft.Authorization/policySetDefinitions",
		"apiVersion": "2021-06-01",
		"scope": null,
		"properties": {
			"policyType": "Custom",
			"displayName": "Deploy Microsoft Defender for Cloud configuration",
			"description": "Deploy Microsoft Defender for Cloud configuration",
			"metadata": {
				"version": "3.0.0",
				"category": "Security Center"
			},
			"parameters": {
				"emailSecurityContact": {
					"type": "string",
					"metadata": {
						"displayName": "Security contacts email address",
						"description": "Provide email address for Microsoft Defender for Cloud contact details"
					}
				},
				"logAnalytics": {
					"type": "String",
					"metadata": {
						"displayName": "Primary Log Analytics workspace",
						"description": "Select Log Analytics workspace from dropdown list. If this workspace is outside of the scope of the assignment you must manually grant 'Log Analytics Contributor' permissions (or similar) to the policy assignment's principal ID.",
						"strongType": "omsWorkspace"
					}
				},
				"ascExportResourceGroupName": {
					"type": "String",
					"metadata": {
						"displayName": "Resource Group name for the export to Log Analytics workspace configuration",
						"description": "The resource group name where the export to Log Analytics workspace configuration is created. If you enter a name for a resource group that doesn't exist, it'll be created in the subscription. Note that each resource group can only have one export to Log Analytics workspace configured."
					}
				},
				"ascExportResourceGroupLocation": {
					"type": "String",
					"metadata": {
						"displayName": "Resource Group location for the export to Log Analytics workspace configuration",
						"description": "The location where the resource group and the export to Log Analytics workspace configuration are created."
					}
				},
				"enableAscForSql": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForSqlOnVm": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForDns": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForArm": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForOssDb": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForAppServices": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForKeyVault": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForStorage": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForContainers": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForServers": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				}
			},
			"policyDefinitions": [
				{
					"policyDefinitionReferenceId": "defenderForOssDb",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/44433aa3-7ec2-4002-93ea-65c65ff0310a",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForOssDb')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForVM",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/8e86a5b6-b9bd-49d1-8e21-4bb8a0862222",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForServers')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForSqlServerVirtualMachines",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/50ea7265-7d8c-429e-9a7d-ca1f410191c3",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForSqlOnVm')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForAppServices",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b40e7bcd-a1e5-47fe-b9cf-2f534d0bfb7d",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForAppServices')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForStorageAccounts",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/74c30959-af11-47b3-9ed2-a26e03f427a3",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForStorage')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderforContainers",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/c9ddb292-b203-4738-aead-18e2716e858f",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForContainers')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForKeyVaults",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/1f725891-01c0-420a-9059-4fa46cb770b7",
					"parameters": {
						"Effect": {
							"value": "[parameters('enableAscForKeyVault')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForDns",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/2370a3c1-4a25-4283-a91a-c9c1a145fb2f",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForDns')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForArm",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b7021b2b-08fd-4dc0-9de7-3c6ece09faf9",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForArm')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForSqlPaas",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b99b73e7-074b-4089-9395-b7236f094491",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForSql')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "securityEmailContact",
					"policyDefinitionId": "${root_scope_resource_id}/providers/Microsoft.Authorization/policyDefinitions/Deploy-ASC-SecurityContacts",
					"parameters": {
						"emailSecurityContact": {
							"value": "[parameters('emailSecurityContact')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "ascExport",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/ffb6f416-7bd2-4488-8828-56585fef2be9",
					"parameters": {
						"resourceGroupName": {
							"value": "[parameters('ascExportResourceGroupName')]"
						},
						"resourceGroupLocation": {
							"value": "[parameters('ascExportResourceGroupLocation')]"
						},
						"workspaceResourceId": {
							"value": "[parameters('logAnalytics')]"
						}
					},
					"groupNames": []
				}
			],
			"policyDefinitionGroups": null
		}
	}`)
}

// getSamplePolicySetDefinition_noName returns a policy set definition with no name as a byte slice
// the name field is missing, rather than empty.
func getSamplePolicySetDefinition_noName() []byte {
	return []byte(`{
		"type": "Microsoft.Authorization/policySetDefinitions",
		"apiVersion": "2021-06-01",
		"scope": null,
		"properties": {
			"policyType": "Custom",
			"displayName": "Deploy Microsoft Defender for Cloud configuration",
			"description": "Deploy Microsoft Defender for Cloud configuration",
			"metadata": {
				"version": "3.0.0",
				"category": "Security Center"
			},
			"parameters": {
				"emailSecurityContact": {
					"type": "string",
					"metadata": {
						"displayName": "Security contacts email address",
						"description": "Provide email address for Microsoft Defender for Cloud contact details"
					}
				},
				"logAnalytics": {
					"type": "String",
					"metadata": {
						"displayName": "Primary Log Analytics workspace",
						"description": "Select Log Analytics workspace from dropdown list. If this workspace is outside of the scope of the assignment you must manually grant 'Log Analytics Contributor' permissions (or similar) to the policy assignment's principal ID.",
						"strongType": "omsWorkspace"
					}
				},
				"ascExportResourceGroupName": {
					"type": "String",
					"metadata": {
						"displayName": "Resource Group name for the export to Log Analytics workspace configuration",
						"description": "The resource group name where the export to Log Analytics workspace configuration is created. If you enter a name for a resource group that doesn't exist, it'll be created in the subscription. Note that each resource group can only have one export to Log Analytics workspace configured."
					}
				},
				"ascExportResourceGroupLocation": {
					"type": "String",
					"metadata": {
						"displayName": "Resource Group location for the export to Log Analytics workspace configuration",
						"description": "The location where the resource group and the export to Log Analytics workspace configuration are created."
					}
				},
				"enableAscForSql": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForSqlOnVm": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForDns": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForArm": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForOssDb": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForAppServices": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForKeyVault": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForStorage": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForContainers": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForServers": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				}
			},
			"policyDefinitions": [
				{
					"policyDefinitionReferenceId": "defenderForOssDb",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/44433aa3-7ec2-4002-93ea-65c65ff0310a",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForOssDb')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForVM",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/8e86a5b6-b9bd-49d1-8e21-4bb8a0862222",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForServers')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForSqlServerVirtualMachines",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/50ea7265-7d8c-429e-9a7d-ca1f410191c3",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForSqlOnVm')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForAppServices",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b40e7bcd-a1e5-47fe-b9cf-2f534d0bfb7d",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForAppServices')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForStorageAccounts",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/74c30959-af11-47b3-9ed2-a26e03f427a3",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForStorage')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderforContainers",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/c9ddb292-b203-4738-aead-18e2716e858f",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForContainers')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForKeyVaults",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/1f725891-01c0-420a-9059-4fa46cb770b7",
					"parameters": {
						"Effect": {
							"value": "[parameters('enableAscForKeyVault')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForDns",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/2370a3c1-4a25-4283-a91a-c9c1a145fb2f",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForDns')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForArm",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b7021b2b-08fd-4dc0-9de7-3c6ece09faf9",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForArm')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForSqlPaas",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b99b73e7-074b-4089-9395-b7236f094491",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForSql')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "securityEmailContact",
					"policyDefinitionId": "${root_scope_resource_id}/providers/Microsoft.Authorization/policyDefinitions/Deploy-ASC-SecurityContacts",
					"parameters": {
						"emailSecurityContact": {
							"value": "[parameters('emailSecurityContact')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "ascExport",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/ffb6f416-7bd2-4488-8828-56585fef2be9",
					"parameters": {
						"resourceGroupName": {
							"value": "[parameters('ascExportResourceGroupName')]"
						},
						"resourceGroupLocation": {
							"value": "[parameters('ascExportResourceGroupLocation')]"
						},
						"workspaceResourceId": {
							"value": "[parameters('logAnalytics')]"
						}
					},
					"groupNames": []
				}
			],
			"policyDefinitionGroups": null
		}
	}`)
}

func getSampleArchetypeOverride_valid() []byte {
	return []byte(`{
	"base_archetype": "base",
	"name": "test",
	"policy_assignments_to_add": [
		"test"
	],
	"policy_assignments_to_remove": [
		"test"
	],
	"policy_definitions_to_add": [
		"test"
	],
	"policy_definitions_to_remove": [
		"test"
	],
	"policy_set_definitions_to_add": [
		"test"
	],
	"policy_set_definitions_to_remove": [
		"test"
	],
	"role_assignments_to_add": [
		"test"
	],
	"role_assignments_to_remove": [
		"test"
	]
}`)
}

func getSampleArchetypeOverride_invalid() []byte {
	return []byte(`{
	"base_archetype": "base",
	"name": "test",
	"policy_assignments_to_add":
		"test"
	],
	"policy_assignments_to_remove": [
		"test"
	],
	"policy_definitions_to_add": [
		"test"
	],
	"policy_definitions_to_remove": [
		"test"
	],
	"policy_set_definitions_to_add": [
		"test"
	],
	"policy_set_definitions_to_remove": [
		"test"
	],
	"role_assignments_to_add": [
		"test"
	],
	"role_assignments_to_remove": [
		"test"
	]
}`)
}

func TestProcessorRegex(t *testing.T) {
	fileTypes2Regex := map[string]*regexp.Regexp{
		"alz_architecture_definition": architectureDefinitionRegex,
		"alz_archetype_definition":    archetypeDefinitionRegex,
		"alz_archetype_override":      archetypeOverrideRegex,
		"alz_policy_definition":       policyDefinitionRegex,
		"alz_policy_assignment":       policyAssignmentRegex,
		"alz_policy_set_definition":   policySetDefinitionRegex,
		"alz_role_definition":         roleDefinitionRegex,
	}
	tests := []struct {
		input    string
		expected bool
	}{
		{input: "example.{{ .Type }}.json", expected: true},
		{input: "example.{{ .Type }}.yaml", expected: true},
		{input: "example.{{ .Type }}.yml", expected: true},
		{input: "example.{{ .Type }}.JSON", expected: false},
		{input: "example.{{ .Type }}.YAML", expected: false},
		{input: "example.{{ .Type }}.YML", expected: false},
		{input: "example.{{ .Type }}.txt", expected: false},
		{input: "example.{{ .Type }}", expected: false},
		{input: "example.{{ .Type }}.json.txt", expected: false},
		{input: "example.{{ .Type }}.yaml.txt", expected: false},
		{input: "example.{{ .Type }}.yml.txt", expected: false},
		{input: "example.{{ .Type }}", expected: false},
		{input: "example.{{ .Type }}", expected: false},
		{input: "example.{{ .Type }}", expected: false},
		{input: "example.{{ .Type }}.json.txt", expected: false},
		{input: "example.{{ .Type }}.yaml.txt", expected: false},
		{input: "example.{{ .Type }}.yml.txt", expected: false},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			tmpl, _ := template.New("test").Parse(test.input) // nolint:errcheck

			for ty, rex := range fileTypes2Regex {
				var buf bytes.Buffer

				tmpl.Execute(&buf, struct{ Type string }{Type: ty}) // nolint:errcheck
				t.Run(buf.String(), func(t *testing.T) {
					match := rex.MatchString(buf.String())
					assert.Equal(t, test.expected, match)
				})
			}
		})
	}
}

func TestProcessorRegexPolicyDefaultValues(t *testing.T) {
	fileTypes2Regex := map[string]*regexp.Regexp{
		"alz_policy_default_values": policyDefaultValuesRegex,
	}
	tests := []struct {
		input    string
		expected bool
	}{
		{input: "{{ .Type }}.json", expected: true},
		{input: "{{ .Type }}.yaml", expected: true},
		{input: "{{ .Type }}.yml", expected: true},
		{input: "{{ .Type }}.JSON", expected: false},
		{input: "{{ .Type }}.YAML", expected: false},
		{input: "{{ .Type }}.YML", expected: false},
		{input: "{{ .Type }}.txt", expected: false},
		{input: "{{ .Type }}", expected: false},
		{input: "{{ .Type }}.json.txt", expected: false},
		{input: "{{ .Type }}.yaml.txt", expected: false},
		{input: "{{ .Type }}.yml.txt", expected: false},
		{input: "{{ .Type }}", expected: false},
		{input: "{{ .Type }}", expected: false},
		{input: "{{ .Type }}", expected: false},
		{input: "{{ .Type }}.json.txt", expected: false},
		{input: "{{ .Type }}.yaml.txt", expected: false},
		{input: "{{ .Type }}.yml.txt", expected: false},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			tmpl, _ := template.New("test").Parse(test.input) // nolint:errcheck

			for ty, rex := range fileTypes2Regex {
				var buf bytes.Buffer

				tmpl.Execute(&buf, struct{ Type string }{Type: ty}) // nolint:errcheck
				t.Run(buf.String(), func(t *testing.T) {
					match := rex.MatchString(buf.String())
					assert.Equal(t, test.expected, match)
				})
			}
		})
	}
}
