// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"strings"

	"github.com/google/uuid"
)

const (
	managementGroupIdFmt     = "/providers/Microsoft.Management/managementGroups/%s"
	policyAssignmentIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyAssignments/%s"
	policyDefinitionIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyDefinitions/%s"
	policySetDefinitionIdFmt = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policySetDefinitions/%s"
	roleDefinitionIdFmt      = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/roleDefinitions/%s"
)

// DeploymentType represents a deployment of Azure management group.
// Note: this is not thread safe, and should not be used concurrently without an external mutex.
type DeploymentType struct {
	mgs map[string]*AlzManagementGroup
}

// GetManagementGroup returns the management group with the given name.
func (d *DeploymentType) GetManagementGroup(name string) *AlzManagementGroup {
	if mg, ok := d.mgs[name]; ok {
		return mg
	}
	return nil
}

// ListManagementGroups returns the management group names as a slice of string.
func (d *DeploymentType) ListManagementGroups() []string {
	res := make([]string, len(d.mgs))
	i := 0
	for mgname := range d.mgs {
		res[i] = mgname
		i++
	}
	return res
}

// policyDefinitionToMg returns a map on policy definition names to the deployed management group name.
func (d *DeploymentType) policyDefinitionToMg() map[string]string {
	res := make(map[string]string, 0)
	for mgname, mg := range d.mgs {
		for pdname := range mg.policyDefinitions {
			res[pdname] = mgname
		}
	}
	return res
}

// policyDefinitionToMg returns a map on policy set definition names to the deployed management group name.
func (d *DeploymentType) policySetDefinitionToMg() map[string]string {
	res := make(map[string]string, 0)
	for mgname, mg := range d.mgs {
		for psdname := range mg.policySetDefinitions {
			res[psdname] = mgname
		}
	}
	return res
}

func uuidV5(s ...string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(strings.Join(s, "")))
}
