// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
)

// TestFullLibrary.
func TestFullLibrary(t *testing.T) {
	t.Parallel()
	fs := os.DirFS("./testdata")
	pc := NewProcessorClient(fs)
	res := new(Result)
	assert.NoError(t, pc.Process(res))
	assert.Equal(t, len(res.LibArchetypes["root"].PolicyAssignments), 13)
	assert.Equal(t, len(res.LibArchetypes["root"].PolicyDefinitions), 114)
	assert.Equal(t, len(res.LibArchetypes["root"].PolicySetDefinitions), 12)
	assert.Equal(t, len(res.LibArchetypes["root"].RoleDefinitions), 5)
}

// TestProcessArchetypeDefinitionValid test the processing of a valid archetype definition.
func TestProcessArchetypeDefinitionValid(t *testing.T) {
	t.Parallel()
	sampleData := getSampleArchetypeDefinition_valid()
	res := &Result{
		LibArchetypes: make(map[string]*LibArchetype, 0),
	}

	assert.NoError(t, processArchetype(res, sampleData))
	assert.Equal(t, len(res.LibArchetypes), 1)
	assert.Equal(t, len(res.LibArchetypes["test"].PolicyAssignments), 1)
	assert.Equal(t, len(res.LibArchetypes["test"].PolicyDefinitions), 1)
	assert.Equal(t, len(res.LibArchetypes["test"].PolicySetDefinitions), 1)
	assert.Equal(t, len(res.LibArchetypes["test"].RoleDefinitions), 1)
}

// TestProcessArchetypeDefinition_multipleTopLevelObjects tests that the correct error
// is generated when there as JSON errors in the archetype definition.
func Test_processArchetypeDefinition_invalidJson(t *testing.T) {
	t.Parallel()
	sampleData := getSampleArchetypeDefinition_invalidJson()
	res := &Result{
		LibArchetypes: make(map[string]*LibArchetype, 0),
	}

	assert.ErrorContains(t, processArchetype(res, sampleData), "invalid character '[' after object key")
}

// TestProcessPolicyAssignmentValid tests the processing of a valid policy assignment.
func TestProcessPolicyAssignmentValid(t *testing.T) {
	t.Parallel()
	sampleData := getSamplePolicyAssignment()
	res := &Result{
		PolicyAssignments: make(map[string]*armpolicy.Assignment),
	}

	assert.NoError(t, processPolicyAssignment(res, sampleData))
	assert.Equal(t, len(res.PolicyAssignments), 1)
	assert.Equal(t, *res.PolicyAssignments["Deny-Storage-http"].Name, "Deny-Storage-http")
	assert.Equal(t, *res.PolicyAssignments["Deny-Storage-http"].Properties.DisplayName, "Secure transfer to storage accounts should be enabled")
}

// TestProcessPolicyAssignmentNoName tests that the processing of a assignment
// with a missing name field throws the correct error.
func TestProcessPolicyAssignmentNoName(t *testing.T) {
	t.Parallel()
	sampleData := getSamplePolicyAssignment_noName()
	res := &Result{
		PolicyAssignments: make(map[string]*armpolicy.Assignment),
	}
	assert.ErrorContains(t, processPolicyAssignment(res, sampleData), "policy assignment name is empty or not present")
}

// TestProcessPolicyDefinitionValid tests the processing of a valid policy definition.
func TestProcessPolicyDefinitionValid(t *testing.T) {
	t.Parallel()
	sampleData := getSamplePolicyDefinition()
	res := &Result{
		PolicyDefinitions: make(map[string]*armpolicy.Definition),
	}
	assert.NoError(t, processPolicyDefinition(res, sampleData))
	assert.Equal(t, len(res.PolicyDefinitions), 1)
	assert.Equal(t, *res.PolicyDefinitions["Append-AppService-httpsonly"].Name, "Append-AppService-httpsonly")
	assert.Equal(t, *res.PolicyDefinitions["Append-AppService-httpsonly"].Properties.PolicyType, armpolicy.PolicyTypeCustom)
}

// TestProcessPolicyDefinitionNoName tests that the processing of a definition
// with a missing name field throws the correct error.
func TestProcessPolicyDefinitionNoName(t *testing.T) {
	t.Parallel()
	sampleData := getSamplePolicyDefinition_noName()
	res := &Result{
		PolicyDefinitions: make(map[string]*armpolicy.Definition),
	}
	assert.ErrorContains(t, processPolicyDefinition(res, sampleData), "policy definition name is empty or not present")
}

// TestProcessSetPolicyDefinitionValid tests the processing of a valid policy set definition.
func TestProcessSetPolicyDefinitionValid(t *testing.T) {
	t.Parallel()
	sampleData := getSamplePolicySetDefinition()
	res := &Result{
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
	}

	assert.NoError(t, processPolicySetDefinition(res, sampleData))
	assert.Equal(t, len(res.PolicySetDefinitions), 1)
	assert.Equal(t, *res.PolicySetDefinitions["Deploy-MDFC-Config"].Name, "Deploy-MDFC-Config")
	assert.Equal(t, *res.PolicySetDefinitions["Deploy-MDFC-Config"].Properties.PolicyType, armpolicy.PolicyTypeCustom)
}

// TestProcessPolicySetDefinitionNoName tests that the processing of a set definition
// with a missing name field throws the correct error.
func TestProcessPolicySetDefinitionNoName(t *testing.T) {
	t.Parallel()
	sampleData := getSamplePolicySetDefinition_noName()
	res := &Result{
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
	}

	assert.ErrorContains(t, processPolicySetDefinition(res, sampleData), "policy set definition name is empty or not present")
}

// TestProcessPolicyAssignmentNoData tests the processing of an invalid policy assignment with no data.
func TestProcessPolicyAssignmentNoData(t *testing.T) {
	t.Parallel()
	res := &Result{}
	assert.ErrorContains(t, processPolicyAssignment(res, make([]byte, 0)), "error unmarshalling policy assignment")
}

// TestProcessPolicyDefinitionNoData tests the processing of an invalid policy definition with no data.
func TestProcessPolicyDefinitionNoData(t *testing.T) {
	t.Parallel()
	res := &Result{}
	assert.ErrorContains(t, processPolicyDefinition(res, make([]byte, 0)), "error unmarshalling policy definition")
}

// TestProcessSetPolicyDefinitionNoData tests the processing of an invalid policy set definition with no data.
func TestProcessPolicySetDefinitionNoData(t *testing.T) {
	t.Parallel()
	res := &Result{}
	assert.ErrorContains(t, processPolicySetDefinition(res, make([]byte, 0)), "error unmarshalling policy set definition")
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
