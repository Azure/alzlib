package assets

import "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"

func GetNameFromResourceId(resId string) (string, error) {
	r, err := arm.ParseResourceID(resId)
	if err != nil {
		return "", err
	}
	return r.Name, nil
}

func GetResourceTypeFromResourceId(resId string) (string, error) {
	r, err := arm.ParseResourceID(resId)
	if err != nil {
		return "", err
	}
	return r.ResourceType.Type, nil
}
