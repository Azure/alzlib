// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

package assets

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// PolicySetDefinition represents a policy set definition and embeds the armpolicy.SetDefinition struct.
type PolicySetDefinition struct {
	armpolicy.SetDefinition
}

// NewPolicySetDefinition creates a new PolicySetDefinition from an armpolicy.SetDefinition.
func NewPolicySetDefinition(psd armpolicy.SetDefinition) *PolicySetDefinition {
	return &PolicySetDefinition{psd}
}

// ReferencedPolicyDefinitionNames returns the names of the policy definitions referenced by the policy set definition.
func (psd *PolicySetDefinition) ReferencedPolicyDefinitionNames() ([]string, error) {
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
func (psd *PolicySetDefinition) PolicyDefinitionReferences() []*armpolicy.DefinitionReference {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil
	}

	return psd.Properties.PolicyDefinitions
}

// Parameter returns the parameter definition for the given name.
func (psd *PolicySetDefinition) Parameter(name string) *armpolicy.ParameterDefinitionsValue {
	if psd == nil || psd.Properties == nil || psd.Properties.Parameters == nil {
		return nil
	}

	ret, ok := psd.Properties.Parameters[name]
	if !ok {
		return nil
	}

	return ret
}
