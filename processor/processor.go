// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// package processor is used to process the library files.
package processor

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
)

// These are the file prefixes for the resource types.
const (
	archetypeDefinitionPrefix = "archetype_definition_"
	archetypeOverridePrefix   = "archetype_override_"
	policyAssignmentPrefix    = "policy_assignment_"
	policyDefinitionPrefix    = "policy_definition_"
	policySetDefinitionPrefix = "policy_set_definition_"
	roleDefinitionPrefix      = "role_definition_"
)

// Result is the structure that gets built by scanning the library files.
type Result struct {
	PolicyDefinitions     map[string]*armpolicy.Definition
	PolicySetDefinitions  map[string]*armpolicy.SetDefinition
	PolicyAssignments     map[string]*armpolicy.Assignment
	RoleDefinitions       map[string]*armauthorization.RoleDefinition
	LibArchetypes         map[string]*LibArchetype
	LibArchetypeOverrides map[string]*LibArchetypeOverride
}

// LibArchetype represents an archetype definition file,
// it used to construct the Archetype struct and is then added to the AlzLib struct.
type LibArchetype struct {
	Name                 string             `json:"name"`
	PolicyAssignments    mapset.Set[string] `json:"policy_assignments"`
	PolicyDefinitions    mapset.Set[string] `json:"policy_definitions"`
	PolicySetDefinitions mapset.Set[string] `json:"policy_set_definitions"`
	RoleDefinitions      mapset.Set[string] `json:"role_definitions"`
}

// LibArchetypeOverride represents an archetype override definition file,
// it used to construct generate a new Archetype struct from an existing
// full archetype and is then added to the AlzLib struct.
type LibArchetypeOverride struct {
	Name                         string             `json:"name"`
	BaseArchetype                string             `json:"base_archetype"`
	PolicyAssignmentsToAdd       mapset.Set[string] `json:"policy_assignments_to_add"`
	PolicyAssignmentsToRemove    mapset.Set[string] `json:"policy_assignments_to_remove"`
	PolicyDefinitionsToAdd       mapset.Set[string] `json:"policy_definitions_to_add"`
	PolicyDefinitionsToRemove    mapset.Set[string] `json:"policy_definitions_to_remove"`
	PolicySetDefinitionsToAdd    mapset.Set[string] `json:"policy_set_definitions_to_add"`
	PolicySetDefinitionsToRemove mapset.Set[string] `json:"policy_set_definitions_to_remove"`
	RoleDefinitionsToAdd         mapset.Set[string] `json:"role_definitions_to_add"`
	RoleDefinitionsToRemove      mapset.Set[string] `json:"role_definitions_to_remove"`
}

// processFunc is the function signature that is used to process different types of lib file.
type processFunc func(result *Result, data []byte) error

// ProcessorClient is the client that is used to process the library files.
type ProcessorClient struct {
	fs fs.FS
}

func NewProcessorClient(fs fs.FS) *ProcessorClient {
	return &ProcessorClient{
		fs: fs,
	}
}

func (client *ProcessorClient) Process(res *Result) error {
	res.LibArchetypes = make(map[string]*LibArchetype)
	res.PolicyAssignments = make(map[string]*armpolicy.Assignment)
	res.PolicyDefinitions = make(map[string]*armpolicy.Definition)
	res.PolicySetDefinitions = make(map[string]*armpolicy.SetDefinition)
	res.RoleDefinitions = make(map[string]*armauthorization.RoleDefinition)
	res.LibArchetypeOverrides = make(map[string]*LibArchetypeOverride)

	// Walk the embedded lib FS and process files
	if err := fs.WalkDir(client.fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error walking directory %s: %w", path, err)
		}
		// Skip directories
		if d.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".json" {
			return nil
		}
		file, err := client.fs.Open(path)
		if err != nil {
			return fmt.Errorf("error opening file %s: %w", path, err)
		}
		return classifyLibFile(res, file, d.Name())
	}); err != nil {
		return err
	}
	return nil
}

// UnmarshalJSON creates a LibArchetype from the supplied JSON bytes.
func (la *LibArchetype) UnmarshalJSON(data []byte) error {
	tmp := struct {
		Name                 string   `json:"name"`
		PolicyAssignments    []string `json:"policy_assignments"`
		PolicyDefinitions    []string `json:"policy_definitions"`
		PolicySetDefinitions []string `json:"policy_set_definitions"`
		RoleDefinitions      []string `json:"role_definitions"`
	}{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	la.Name = tmp.Name
	la.PolicyAssignments = mapset.NewSet[string](tmp.PolicyAssignments...)
	la.PolicyDefinitions = mapset.NewSet[string](tmp.PolicyDefinitions...)
	la.PolicySetDefinitions = mapset.NewSet[string](tmp.PolicySetDefinitions...)
	la.RoleDefinitions = mapset.NewSet[string](tmp.RoleDefinitions...)
	return nil
}

func (lao *LibArchetypeOverride) UnmarshalJSON(data []byte) error {
	tmp := struct {
		Name                         string   `json:"name"`
		BaseArchetype                string   `json:"base_archetype"`
		PolicyAssignmentsToAdd       []string `json:"policy_assignments_to_add"`
		PolicyAssignmentsToRemove    []string `json:"policy_assignments_to_remove"`
		PolicyDefinitionsToAdd       []string `json:"policy_definitions_to_add"`
		PolicyDefinitionsToRemove    []string `json:"policy_definitions_to_remove"`
		PolicySetDefinitionsToAdd    []string `json:"policy_set_definitions_to_add"`
		PolicySetDefinitionsToRemove []string `json:"policy_set_definitions_to_remove"`
		RoleDefinitionsToAdd         []string `json:"role_definitions_to_add"`
		RoleDefinitionsToRemove      []string `json:"role_definitions_to_remove"`
	}{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	lao.Name = tmp.Name
	lao.BaseArchetype = tmp.BaseArchetype
	lao.PolicyAssignmentsToAdd = mapset.NewSet[string](tmp.PolicyAssignmentsToAdd...)
	lao.PolicyAssignmentsToRemove = mapset.NewSet[string](tmp.PolicyAssignmentsToRemove...)
	lao.PolicyDefinitionsToAdd = mapset.NewSet[string](tmp.PolicyDefinitionsToAdd...)
	lao.PolicyDefinitionsToRemove = mapset.NewSet[string](tmp.PolicyDefinitionsToRemove...)
	lao.PolicySetDefinitionsToAdd = mapset.NewSet[string](tmp.PolicySetDefinitionsToAdd...)
	lao.PolicySetDefinitionsToRemove = mapset.NewSet[string](tmp.PolicySetDefinitionsToRemove...)
	lao.RoleDefinitionsToAdd = mapset.NewSet[string](tmp.RoleDefinitionsToAdd...)
	lao.RoleDefinitionsToRemove = mapset.NewSet[string](tmp.RoleDefinitionsToRemove...)
	return nil
}

// classifyLibFile identifies the supplied file and adds calls the appropriate processFunc.
func classifyLibFile(res *Result, file fs.File, name string) error {
	err := error(nil)

	// process by file type
	switch n := strings.ToLower(name); {
	// if the file is a policy definition
	case strings.HasPrefix(n, policyDefinitionPrefix):
		err = readAndProcessFile(res, file, processPolicyDefinition)

	// if the file is a policy set definition
	case strings.HasPrefix(n, policySetDefinitionPrefix):
		err = readAndProcessFile(res, file, processPolicySetDefinition)

	// if the file is a policy assignment
	case strings.HasPrefix(n, policyAssignmentPrefix):
		err = readAndProcessFile(res, file, processPolicyAssignment)

	// if the file is a role definition
	case strings.HasPrefix(n, roleDefinitionPrefix):
		err = readAndProcessFile(res, file, processRoleDefinition)

	// if the file is an archetype definition
	case strings.HasPrefix(n, archetypeDefinitionPrefix):
		err = readAndProcessFile(res, file, processArchetype)

	// if the file is an archetype override
	case strings.HasPrefix(n, archetypeOverridePrefix):
		err = readAndProcessFile(res, file, processArchetypeOverride)
	}

	if err != nil {
		err = fmt.Errorf("error processing file: %w", err)
	}

	return err
}

// processArchetype is a processFunc that reads the archetype_definition
// bytes, processes, then adds the created LibArchetypeDefinition to the AlzLib.
func processArchetype(res *Result, data []byte) error {
	la := new(LibArchetype)

	if err := json.Unmarshal(data, la); err != nil {
		return fmt.Errorf("error processing archetype definition: %w", err)
	}
	if _, exists := res.LibArchetypes[la.Name]; exists {
		return fmt.Errorf("archetype with name %s already exists", la.Name)
	}
	res.LibArchetypes[la.Name] = la
	return nil
}

// processArchetypeOverride is a processFunc that reads the archetype_override
// bytes, processes, then adds the created LibArchetypeDefinition to the AlzLib.
func processArchetypeOverride(res *Result, data []byte) error {
	lao := new(LibArchetypeOverride)
	if err := json.Unmarshal(data, lao); err != nil {
		return fmt.Errorf("error processing archetype definition: %w", err)
	}
	if _, exists := res.LibArchetypeOverrides[lao.Name]; exists {
		return fmt.Errorf("archetype override with name %s already exists", lao.Name)
	}
	res.LibArchetypeOverrides[lao.Name] = lao
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_assignment
// bytes, processes, then adds the created armpolicy.Assignment to the AlzLib.
func processPolicyAssignment(res *Result, data []byte) error {
	pa := new(armpolicy.Assignment)
	if err := json.Unmarshal(data, pa); err != nil {
		return fmt.Errorf("error unmarshalling policy assignment: %w", err)
	}
	if pa.Name == nil || *pa.Name == "" {
		return fmt.Errorf("policy assignment name is empty or not present")
	}
	if _, exists := res.PolicyAssignments[*pa.Name]; exists {
		return fmt.Errorf("policy assignment with name %s already exists", *pa.Name)
	}
	res.PolicyAssignments[*pa.Name] = pa
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_definition
// bytes, processes, then adds the created armpolicy.Definition to the AlzLib.
func processPolicyDefinition(res *Result, data []byte) error {
	pd := new(armpolicy.Definition)
	if err := json.Unmarshal(data, pd); err != nil {
		return fmt.Errorf("error unmarshalling policy definition: %w", err)
	}
	if pd.Name == nil || *pd.Name == "" {
		return fmt.Errorf("policy definition name is empty or not present")
	}
	if _, exists := res.PolicyDefinitions[*pd.Name]; exists {
		return fmt.Errorf("policy definition with name %s already exists", *pd.Name)
	}
	res.PolicyDefinitions[*pd.Name] = pd
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_set_definition
// bytes, processes, then adds the created armpolicy.SetDefinition to the AlzLib.
func processPolicySetDefinition(res *Result, data []byte) error {
	psd := new(armpolicy.SetDefinition)
	if err := json.Unmarshal(data, psd); err != nil {
		return fmt.Errorf("error unmarshalling policy set definition: %w", err)
	}
	if psd.Name == nil || *psd.Name == "" {
		return fmt.Errorf("policy set definition name is empty or not present")
	}
	if _, exists := res.PolicySetDefinitions[*psd.Name]; exists {
		return fmt.Errorf("policy set definition with name %s already exists", *psd.Name)
	}
	res.PolicySetDefinitions[*psd.Name] = psd
	return nil
}

func processRoleDefinition(res *Result, data []byte) error {
	rd := new(armauthorization.RoleDefinition)
	if err := json.Unmarshal(data, rd); err != nil {
		return fmt.Errorf("error unmarshalling role definition: %w", err)
	}
	if rd.Name == nil || *rd.Name == "" {
		return fmt.Errorf("policy set definition name is empty or not present")
	}
	if _, exists := res.PolicySetDefinitions[*rd.Name]; exists {
		return fmt.Errorf("policy set definition with name %s already exists", *rd.Name)
	}
	// Use roleName here not the name, which is a GUID
	res.RoleDefinitions[*rd.Properties.RoleName] = rd
	return nil
}

// readAndProcessFile reads the file bytes at the supplied path and processes it using the supplied processFunc.
func readAndProcessFile(res *Result, file fs.File, processFn processFunc) error {
	s, err := file.Stat()
	if err != nil {
		return err
	}
	data := make([]byte, s.Size())
	defer file.Close() // nolint: errcheck
	if _, err := file.Read(data); err != nil {
		return err
	}

	// pass the  data to the supplied process function
	if err := processFn(res, data); err != nil {
		return err
	}
	return nil
}
