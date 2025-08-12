// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package assets

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// PolicySetDefinitionVersion represents a version of a policy set definition with version
// information. It embeds the armpolicy.SetDefinitionVersion struct and provides additional methods
// to work with it.
type PolicySetDefinitionVersion struct {
	armpolicy.SetDefinitionVersion
}

// NewPolicySetDefinitionVersion creates a new PolicySetDefinitionVersion from an armpolicy.SetDefinitionVersion.
func NewPolicySetDefinitionVersion(psd armpolicy.SetDefinitionVersion) *PolicySetDefinitionVersion {
	return &PolicySetDefinitionVersion{psd}
}

// ReferencedPolicyDefinitionNames returns the names of the policy definitions referenced by the policy set definition.
func (psd *PolicySetDefinitionVersion) ReferencedPolicyDefinitionNames() ([]string, error) {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil, errors.New("policy set definition is nil, missing properties or policy definitions")
	}

	names := make([]string, len(psd.Properties.PolicyDefinitions))

	for i, pd := range psd.Properties.PolicyDefinitions {
		resID, err := arm.ParseResourceID(*pd.PolicyDefinitionID)
		if err != nil {
			return nil, err
		}

		names[i] = resID.Name
	}

	return names, nil
}

// PolicyDefinitionReferences returns the policy definition references for the policy set definition.
func (psd *PolicySetDefinitionVersion) PolicyDefinitionReferences() []*armpolicy.DefinitionReference {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil
	}

	return psd.Properties.PolicyDefinitions
}

// Parameter returns the parameter definition for the given name.
func (psd *PolicySetDefinitionVersion) Parameter(name string) *armpolicy.ParameterDefinitionsValue {
	if psd == nil || psd.Properties == nil || psd.Properties.Parameters == nil {
		return nil
	}

	ret, ok := psd.Properties.Parameters[name]
	if !ok {
		return nil
	}

	return ret
}

// GetName returns the name of the policy set definition.
func (psd *PolicySetDefinitionVersion) GetName() *string {
	if psd == nil {
		return nil
	}

	return psd.Name
}

// GetVersion returns the version of the policy set definition.
func (psd *PolicySetDefinitionVersion) GetVersion() *string {
	if psd == nil || psd.Properties == nil {
		return nil
	}

	return psd.Properties.Version
}
