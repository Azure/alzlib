package alzlib

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

// PolicyAssignmentsParameterValues represents a data structure for replacing policy parameters.
// The first map key is the assignment name, the second is the parameter name, and the value is
// the parameter values value (an ARM SDK type).
type PolicyAssignmentsParameterValues map[string]map[string]*armpolicy.ParameterValuesValue

// Merge merges the other PolicyAssignmentsParameterValues into this one.
func (papv PolicyAssignmentsParameterValues) Merge(other PolicyAssignmentsParameterValues) PolicyAssignmentsParameterValues {
	if other == nil {
		return papv
	}
	for assignment, parametermap := range other {
		// If assignment doesn't exist in original, create it.
		if _, ok := papv[assignment]; !ok {
			papv[assignment] = make(map[string]*armpolicy.ParameterValuesValue)
		}
		// Merge the parameter values.
		for parameter, value := range parametermap {
			papv[assignment][parameter] = value
		}
	}
	return papv
}

// getWellKnownPolicyAssignmentParameterValues is used by the *Archetype.WithWellKnownPolicyValues() method to
// set the values for well-known policy assignment parameters.
// It takes the well known values, e.g. for LA workspace and location, and merges them with the policy assignments
// known to the ALZ library.
func getWellKnownPolicyAssignmentParameterValues(wkpv *WellKnownPolicyValues) PolicyAssignmentsParameterValues {
	return PolicyAssignmentsParameterValues{
		"Deploy-AzActivity-Log": {
			"logAnalytics": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-AzSqlDb-Auditing": {
			"logAnalyticsWorkspaceId": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-Log-Analytics": {
			"workspaceRegion": {
				Value: wkpv.DefaultLocation,
			},
			"automationRegion": {
				Value: wkpv.DefaultLocation,
			},
		},
		"Deploy-MDFC-Config": {
			"logAnalytics": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
			"ascExportResourceGroupLocation": {
				Value: wkpv.DefaultLocation,
			},
		},
		"Deploy-Resource-Diag": {
			"logAnalytics": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-VM-Monitoring": {
			"logAnalytics_1": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-VMSS-Monitoring": {
			"logAnalytics_1": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
	}
}
