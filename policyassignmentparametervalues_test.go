package alzlib

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func TestPolicyAssignmentsParameterValues_Merge(t *testing.T) {
	// Create two PolicyAssignmentsParameterValues to merge.
	p1 := PolicyAssignmentsParameterValues{
		"assignment1": {
			"param1": &armpolicy.ParameterValuesValue{Value: "value1"},
			"param2": &armpolicy.ParameterValuesValue{Value: "value2"},
		},
	}
	p2 := PolicyAssignmentsParameterValues{
		"assignment1": {
			"param2": &armpolicy.ParameterValuesValue{Value: "value3"},
			"param3": &armpolicy.ParameterValuesValue{Value: "value4"},
		},
		"assignment2": {
			"param4": &armpolicy.ParameterValuesValue{Value: "value5"},
			"param5": &armpolicy.ParameterValuesValue{Value: "value6"},
		},
	}

	// Merge the two PolicyAssignmentsParameterValues.
	result := p1.Merge(p2)

	// Check that the merged PolicyAssignmentsParameterValues are correct.
	if len(result) != 2 {
		t.Errorf("Merge returned an incorrect number of assignments")
	}
	if len(result["assignment1"]) != 3 {
		t.Errorf("Merge returned an incorrect number of parameters for assignment1")
	}
	if len(result["assignment2"]) != 2 {
		t.Errorf("Merge returned an incorrect number of parameters for assignment2")
	}
	if result["assignment1"]["param1"].Value != "value1" || result["assignment1"]["param2"].Value != "value3" || result["assignment1"]["param3"].Value != "value4" {
		t.Errorf("Merge returned incorrect parameter values for assignment1")
	}
	if result["assignment2"]["param4"].Value != "value5" || result["assignment2"]["param5"].Value != "value6" {
		t.Errorf("Merge returned incorrect parameter values for assignment2")
	}
}
