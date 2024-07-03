package checks

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/assets"
)

func TestCheckAllDefinitionsAreReferenced(t *testing.T) {
	az := alzlib.NewAlzLib(nil)
	azElem := reflect.ValueOf(az).Elem()
	field := azElem.FieldByName("policyDefinitions")
	fieldPtr := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	pd := fieldPtr.Interface().(map[string]*assets.PolicyDefinition)
	pd["policy1"] = &assets.PolicyDefinition{}
	pd["policy2"] = &assets.PolicyDefinition{}

	field = azElem.FieldByName("policySetDefinitions")
	fieldPtr = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	psd := fieldPtr.Interface().(map[string]*assets.PolicySetDefinition)
	psd["policySet1"] = &assets.PolicySetDefinition{}
	psd["policySet2"] = &assets.PolicySetDefinition{}

	field = azElem.FieldByName("roleDefinitions")
	fieldPtr = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	rd := fieldPtr.Interface().(map[string]*assets.RoleDefinition)
	rd["role1"] = &assets.RoleDefinition{}
	rd["role2"] = &assets.RoleDefinition{}

	// az = &alzlib.AlzLib{
	// 	PolicyDefinitions:    []string{"policy1", "policy2"},
	// 	PolicySetDefinitions: []string{"policySet1", "policySet2"},
	// 	RoleDefinitions:      []string{"role1", "role2"},
	// 	ArchetypesFunc: func() []string {
	// 		return []string{"archetype1", "archetype2"}
	// 	},
	// 	ArchetypeFunc: func(name string) (*alzlib.Archetype, error) {
	// 		switch name {
	// 		case "archetype1":
	// 			return &alzlib.Archetype{
	// 				PolicyDefinitions:    []string{"policy1"},
	// 				PolicySetDefinitions: []string{"policySet1"},
	// 				RoleDefinitions:      []string{"role1"},
	// 			}, nil
	// 		case "archetype2":
	// 			return &alzlib.Archetype{
	// 				PolicyDefinitions:    []string{"policy2"},
	// 				PolicySetDefinitions: []string{"policySet2"},
	// 				RoleDefinitions:      []string{"role2"},
	// 			}, nil
	// 		default:
	// 			return nil, fmt.Errorf("unknown archetype: %s", name)
	// 		}
	// 	},
	// }

	err := CheckAllDefinitionsAreReferenced(az)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}

	// Test case with unreferenced definitions
	// az.PolicyDefinitions = []string{"policy1", "policy2", "policy3"}
	// az.PolicySetDefinitions = []string{"policySet1", "policySet2", "policySet3"}
	// az.RoleDefinitions = []string{"role1", "role2", "role3"}

	err = CheckAllDefinitionsAreReferenced(az)
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}
