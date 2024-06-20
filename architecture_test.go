package alzlib

import "testing"

func TestRootMgs(t *testing.T) {
	az := NewAlzLib(nil)
	arch := NewArchitecture("test", az)
	mg1 := newArchitectureManagementGroup("mg1", "Management Group 1", true, arch)
	mg2 := newArchitectureManagementGroup("mg2", "Management Group 2", true, arch)
	mg3 := newArchitectureManagementGroup("mg3", "Management Group 3", true, arch)
	// mg4 is a lone root management group
	mg4 := newArchitectureManagementGroup("mg4", "Management Group 4", true, arch)

	// Set mg2 as the parent of mg1
	mg1.parent = mg2
	mg2.children.Add(mg1)

	// Set mg3 as the parent of mg2
	mg2.parent = mg3
	mg3.children.Add(mg2)

	arch.mgs[mg1.id] = mg1
	arch.mgs[mg2.id] = mg2
	arch.mgs[mg3.id] = mg3
	arch.mgs[mg4.id] = mg4

	expected := []*ArchitectureManagementGroup{mg3, mg4}
	actual := arch.RootMgs()

	if len(actual) != len(expected) {
		t.Errorf("Expected %d root management groups, but got %d", len(expected), len(actual))
	}

	for i := range expected {
		if expected[i] != actual[i] {
			t.Errorf("Expected root management group %s, but got %s", expected[i].id, actual[i].id)
		}
	}
}
