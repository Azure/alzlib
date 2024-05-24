// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// These are the file prefixes for the resource types.
const (
	archetypeDefinitionPrefix = "archetype_definition_"
	archetypeOverridePrefix   = "archetype_override_"
	policyAssignmentPrefix    = "policy_assignment_"
	policyDefinitionPrefix    = "policy_definition_"
	policySetDefinitionPrefix = "policy_set_definition_"
	roleDefinitionPrefix      = "role_definition_"
	policyDefaultValuesPrefix = "policy_default_values_"
)

// Result is the structure that gets built by scanning the library files.
type Result struct {
	PolicyDefinitions      map[string]*armpolicy.Definition
	PolicySetDefinitions   map[string]*armpolicy.SetDefinition
	PolicyAssignments      map[string]*armpolicy.Assignment
	RoleDefinitions        map[string]*armauthorization.RoleDefinition
	LibArchetypes          map[string]*LibArchetype
	LibArchetypeOverrides  map[string]*LibArchetypeOverride
	LibDefaultPolicyValues map[string]*LibDefaultPolicyValues
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
	res.LibDefaultPolicyValues = make(map[string]*LibDefaultPolicyValues)

	// Walk the embedded lib FS and process files
	if err := fs.WalkDir(client.fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("ProcessorClient.Process: error walking directory %s: %w", path, err)
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
			return fmt.Errorf("ProcessorClient.Process: error opening file %s: %w", path, err)
		}
		return classifyLibFile(res, file, d.Name())
	}); err != nil {
		return err
	}
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

		// if the file is an policy default values file
	case strings.HasPrefix(n, policyDefaultValuesPrefix):
		err = readAndProcessFile(res, file, processDefaultPolicyValues)
	}

	if err != nil {
		err = fmt.Errorf("classifyLibFile: error processing file: %w", err)
	}

	return err
}

// processDefaultPolicyValues is a processFunc that reads the default_policy_values
// bytes, processes, then adds the created LibArchetypeDefinition to the result.
func processDefaultPolicyValues(res *Result, data []byte) error {
	lpv := new(LibDefaultPolicyValues)
	if err := json.Unmarshal(data, lpv); err != nil {
		return fmt.Errorf("processDefaultPolicyValues: error processing default policy values: %w", err)
	}
	for _, d := range lpv.Defaults {
		if _, exists := res.LibDefaultPolicyValues[d.DefaultName]; exists {
			return fmt.Errorf("processDefaultPolicyValues: default policy values with name `%s` already exists", d.DefaultName)
		}
		res.LibDefaultPolicyValues[d.DefaultName] = lpv
	}
	return nil
}

// processArchetype is a processFunc that reads the archetype_definition
// bytes, processes, then adds the created LibArchetypeDefinition to the result.
func processArchetype(res *Result, data []byte) error {
	la := new(LibArchetype)

	if err := json.Unmarshal(data, la); err != nil {
		return fmt.Errorf("processArchetype: error processing archetype definition: %w", err)
	}
	if _, exists := res.LibArchetypes[la.Name]; exists {
		return fmt.Errorf("processArchetype: archetype with name `%s` already exists", la.Name)
	}
	res.LibArchetypes[la.Name] = la
	return nil
}

// processArchetypeOverride is a processFunc that reads the archetype_override
// bytes, processes, then adds the created LibArchetypeDefinition to the result.
func processArchetypeOverride(res *Result, data []byte) error {
	lao := new(LibArchetypeOverride)
	if err := json.Unmarshal(data, lao); err != nil {
		return fmt.Errorf("processArchetypeOverride: error processing archetype definition: %w", err)
	}
	if _, exists := res.LibArchetypeOverrides[lao.Name]; exists {
		return fmt.Errorf("processArchetypeOverride: archetype override with name `%s` already exists", lao.Name)
	}
	res.LibArchetypeOverrides[lao.Name] = lao
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_assignment
// bytes, processes, then adds the created armpolicy.Assignment to the result.
func processPolicyAssignment(res *Result, data []byte) error {
	pa := new(armpolicy.Assignment)
	if err := json.Unmarshal(data, pa); err != nil {
		return fmt.Errorf("processPolicyAssignment: error unmarshalling policy assignment: %w", err)
	}
	if pa.Name == nil || *pa.Name == "" {
		return fmt.Errorf("processPolicyAssignment: policy assignment name is empty or not present")
	}
	if _, exists := res.PolicyAssignments[*pa.Name]; exists {
		return fmt.Errorf("processPolicyAssignment: policy assignment with name `%s` already exists", *pa.Name)
	}
	res.PolicyAssignments[*pa.Name] = pa
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_definition
// bytes, processes, then adds the created armpolicy.Definition to the result.
func processPolicyDefinition(res *Result, data []byte) error {
	pd := new(armpolicy.Definition)
	if err := json.Unmarshal(data, pd); err != nil {
		return fmt.Errorf("processPolicyDefinition: error unmarshalling policy definition: %w", err)
	}
	if pd.Name == nil || *pd.Name == "" {
		return fmt.Errorf("processPolicyDefinition: policy definition name is empty or not present")
	}
	if _, exists := res.PolicyDefinitions[*pd.Name]; exists {
		return fmt.Errorf("processPolicyDefinition: policy definition with name `%s` already exists", *pd.Name)
	}
	res.PolicyDefinitions[*pd.Name] = pd
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_set_definition
// bytes, processes, then adds the created armpolicy.SetDefinition to the result.
func processPolicySetDefinition(res *Result, data []byte) error {
	psd := new(armpolicy.SetDefinition)
	if err := json.Unmarshal(data, psd); err != nil {
		return fmt.Errorf("processPolicySetDefinition: error unmarshalling policy set definition: %w", err)
	}
	if psd.Name == nil || *psd.Name == "" {
		return fmt.Errorf("processPolicySetDefinition: policy set definition name is empty or not present")
	}
	if _, exists := res.PolicySetDefinitions[*psd.Name]; exists {
		return fmt.Errorf("processPolicySetDefinition: policy set definition with name `%s` already exists", *psd.Name)
	}
	res.PolicySetDefinitions[*psd.Name] = psd
	return nil
}

// processRoleDefinition is a processFunc that reads the role_definition
// bytes, processes, then adds the created armpolicy.SetDefinition to the result.
func processRoleDefinition(res *Result, data []byte) error {
	rd := new(armauthorization.RoleDefinition)
	if err := json.Unmarshal(data, rd); err != nil {
		return fmt.Errorf("processRoleDefinition: error unmarshalling role definition: %w", err)
	}
	if rd.Name == nil || *rd.Name == "" {
		return fmt.Errorf("processRoleDefinition: policy set definition name is empty or not present")
	}
	if _, exists := res.PolicySetDefinitions[*rd.Name]; exists {
		return fmt.Errorf("processRoleDefinition: policy set definition with name `%s` already exists", *rd.Name)
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
