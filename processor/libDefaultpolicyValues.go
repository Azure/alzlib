package processor

// LibDefaultPolicyValues represents the default policy values that allow a single value to be mapped into different assignments.
type LibDefaultPolicyValues struct {
	Defaults []struct {
		DefaultName       string `json:"default_name"`
		PolicyAssignments []struct {
			PolicyAssignmentName string   `json:"policy_assignment_name"`
			ParameterNames       []string `json:"parameter_names"`
		} `json:"policy_assignments"`
	} `json:"defaults"`
}
