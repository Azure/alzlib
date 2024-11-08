package deployment

import "testing"

func TestPolicyRoleAssignmentError_Error(t *testing.T) {
	err := NewPolicyRoleAssignmentError("testAssignment", "testScope", "testParameter", "pdRef1", []string{"role1", "role2"})
	expected := "PolicyRoleAssignmentError: could not generate role assignment for assignment `testAssignment` assigned at scope `testScope`. A new role assignment should be created at scope of the definition referenced by `pdRef1`, using parameter name `testParameter`, for the following role definition ids: `role1, role2`"
	if err.Error() != expected {
		t.Errorf("expected %s, got %s", expected, err.Error())
	}
}

func TestPolicyRoleAssignmentErrors_Error(t *testing.T) {
	err1 := NewPolicyRoleAssignmentError("testAssignment1", "testScope1", "testParameter1", "pdRef1", []string{"role1", "role2"})
	err2 := NewPolicyRoleAssignmentError("testAssignment2", "testScope2", "testParameter2", "pdRef2", []string{"role3", "role4"})
	errors := PolicyRoleAssignmentErrors{
		errors: []*PolicyRoleAssignmentError{err1, err2}}
	expected := "PolicyRoleAssignmentError: could not generate role assignment for assignment `testAssignment1` assigned at scope `testScope1`. A new role assignment should be created at scope of the definition referenced by `pdRef1`, using parameter name `testParameter1`, for the following role definition ids: `role1, role2`\nPolicyRoleAssignmentError: could not generate role assignment for assignment `testAssignment2` assigned at scope `testScope2`. A new role assignment should be created at scope of the definition referenced by `pdRef2`, using parameter name `testParameter2`, for the following role definition ids: `role3, role4`"
	if errors.Error() != expected {
		t.Errorf("expected %s, got %s", expected, errors.Error())
	}
}

func TestPolicyRoleAssignmentErrors_Add(t *testing.T) {
	errors := NewPolicyRoleAssignmentErrors()
	err1 := NewPolicyRoleAssignmentError("testAssignment1", "testScope1", "testParameter1", "pdRef1", []string{"role1", "role2"})
	err2 := NewPolicyRoleAssignmentError("testAssignment2", "testScope2", "testParameter2", "pdRef2", []string{"role3", "role4"})

	errors.Add(err1)
	errors.Add(err2)

	expected := "PolicyRoleAssignmentError: could not generate role assignment for assignment `testAssignment1` assigned at scope `testScope1`. A new role assignment should be created at scope of the definition referenced by `pdRef1`, using parameter name `testParameter1`, for the following role definition ids: `role1, role2`\n---\nPolicyRoleAssignmentError: could not generate role assignment for assignment `testAssignment2` assigned at scope `testScope2`. A new role assignment should be created at scope of the definition referenced by `pdRef2`, using parameter name `testParameter2`, for the following role definition ids: `role3, role4`"
	if errors.Error() != expected {
		t.Errorf("expected %s, got %s", expected, errors.Error())
	}
}
