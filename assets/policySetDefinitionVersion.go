package assets

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// PolicySetDefinitionVersion represents a version of a policy set definition with version information.
// It embeds the armpolicy.SetDefinitionVersion struct and provides additional methods to work with it.
type PolicySetDefinitionVersion struct {
	armpolicy.SetDefinitionVersion
}

func NewPolicySetDefinitionVersion(psd armpolicy.SetDefinitionVersion) *PolicySetDefinitionVersion {
	return &PolicySetDefinitionVersion{psd}
}

func (psd *PolicySetDefinitionVersion) ReferencedPolicyDefinitionNames() ([]string, error) {
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

func (psd *PolicySetDefinitionVersion) PolicyDefinitionReferences() []*armpolicy.DefinitionReference {
	if psd == nil || psd.Properties == nil || psd.Properties.PolicyDefinitions == nil {
		return nil
	}
	return psd.Properties.PolicyDefinitions
}

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

func (psd *PolicySetDefinitionVersion) GetName() *string {
	if psd == nil {
		return nil
	}
	return psd.Name
}

func (psd *PolicySetDefinitionVersion) GetVersion() *string {
	if psd == nil || psd.Properties == nil {
		return nil
	}
	return psd.Properties.Version
}
