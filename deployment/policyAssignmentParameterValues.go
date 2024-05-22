package deployment

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

type PolicyAssignmentsParameterValues map[string]map[string]*armpolicy.ParameterValuesValue
