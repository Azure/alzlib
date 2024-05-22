package assets

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/brunoga/deep"
)

type PolicySetDefinition struct {
	armpolicy.SetDefinition
}

func NewPolicySetDefinition(psd armpolicy.SetDefinition) *PolicySetDefinition {
	return &PolicySetDefinition{psd}
}

func (psd *PolicySetDefinition) GetReferencedPolicyDefinitionNames() ([]string, error) {
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

func (psd *PolicySetDefinition) GetPolicyDefinitionReferences() ([]*armpolicy.DefinitionReference, error) {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil, errors.New("policy set definition is nil, missing properties or policy definitions")
	}
	return deep.Copy(psd.Properties.PolicyDefinitions)
}
