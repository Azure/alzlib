// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

type PolicySetDefinition struct {
	armpolicy.SetDefinition
}

func NewPolicySetDefinition(psd armpolicy.SetDefinition) *PolicySetDefinition {
	return &PolicySetDefinition{psd}
}

func (psd *PolicySetDefinition) ReferencedPolicyDefinitionNames() ([]string, error) {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil, errors.New("policy set definition is nil, missing properties or policy definitions")
	}
	names := make([]string, len(psd.Properties.PolicyDefinitions))
	for i, pd := range psd.Properties.PolicyDefinitions {
		resId, err := arm.ParseResourceID(*pd.PolicyDefinitionID)
		if err != nil {
			return nil, err
		}
		names[i] = resId.Name
	}
	return names, nil
}

func (psd *PolicySetDefinition) PolicyDefinitionReferences() ([]*armpolicy.DefinitionReference, error) {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil, errors.New("policy set definition is nil, missing properties or policy definitions")
	}
	return psd.Properties.PolicyDefinitions, nil
}

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
