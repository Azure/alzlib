package checks

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func CheckResourceTypeIsCorrect(anyType any) error {
	switch anyType := anyType.(type) {
	case *armpolicy.Definition:
		if anyType.Type == nil || *anyType.Type != "Microsoft.Authorization/policyDefinitions" {
			return errors.New("resource is not a policy definition")
		}
	case *armpolicy.SetDefinition:
		if anyType.Type == nil || *anyType.Type != "Microsoft.Authorization/policySetDefinitions" {
			return errors.New("resource is not a policy set definition")
		}
	}
	return nil
}
