// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// These are the file prefixes for the resource types.
const (
	architectureDefinitionSuffix = ".+\\.alz_architecture_definition\\.(?i:json|yaml|yml)$"
	archetypeDefinitionSuffix    = ".+\\.alz_archetype_definition\\.(?i:json|yaml|yml)$"
	archetypeOverrideSuffix      = ".+\\.alz_archetype_override\\.(?i:json|yaml|yml)$"
	policyAssignmentSuffix       = ".+\\.alz_policy_assignment\\.(?i:json|yaml|yml)$"
	policyDefinitionSuffix       = ".+\\.alz_policy_definition\\.(?i:json|yaml|yml)$"
	policySetDefinitionSuffix    = ".+\\.alz_policy_set_definition\\.(?i:json|yaml|yml)$"
	roleDefinitionSuffix         = ".+\\.alz_role_definition\\.(?i:json|yaml|yml)$"
	policyDefaultValuesSuffix    = ".+\\.alz_policy_default_values\\.(?i:json|yaml|yml)$"
)

var supportedFileTypes = []string{".json", ".yaml", ".yml"}

var architectureDefinitionRegex = regexp.MustCompile(architectureDefinitionSuffix)
var archetypeDefinitionRegex = regexp.MustCompile(archetypeDefinitionSuffix)
var archetypeOverrideRegex = regexp.MustCompile(archetypeOverrideSuffix)
var policyAssignmentRegex = regexp.MustCompile(policyAssignmentSuffix)
var policyDefinitionRegex = regexp.MustCompile(policyDefinitionSuffix)
var policySetDefinitionRegex = regexp.MustCompile(policySetDefinitionSuffix)
var roleDefinitionRegex = regexp.MustCompile(roleDefinitionSuffix)
var policyDefaultValuesRegex = regexp.MustCompile(policyDefaultValuesSuffix)

// Result is the structure that gets built by scanning the library files.
type Result struct {
	PolicyDefinitions      map[string]*armpolicy.Definition
	PolicySetDefinitions   map[string]*armpolicy.SetDefinition
	PolicyAssignments      map[string]*armpolicy.Assignment
	RoleDefinitions        map[string]*armauthorization.RoleDefinition
	LibArchetypes          map[string]*LibArchetype
	LibArchetypeOverrides  map[string]*LibArchetypeOverride
	LibDefaultPolicyValues map[string]*LibDefaultPolicyValues
	LibArchitectures       map[string]*LibArchitecture
}

// processFunc is the function signature that is used to process different types of lib file.
type processFunc func(result *Result, data unmarshaler) error

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
	res.LibArchitectures = make(map[string]*LibArchitecture)

	// Walk the embedded lib FS and process files
	if err := fs.WalkDir(client.fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("ProcessorClient.Process: error walking directory %s: %w", path, err)
		}
		// Skip directories
		if d.IsDir() {
			return nil
		}
		// Skip files that are not json or yaml
		if !slices.Contains(supportedFileTypes, strings.ToLower(filepath.Ext(path))) {
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
	case policyDefinitionRegex.MatchString(n):
		err = readAndProcessFile(res, file, processPolicyDefinition)

	// if the file is a policy set definition
	case policySetDefinitionRegex.MatchString(n):
		err = readAndProcessFile(res, file, processPolicySetDefinition)

	// if the file is a policy assignment
	case policyAssignmentRegex.MatchString(n):
		err = readAndProcessFile(res, file, processPolicyAssignment)

	// if the file is a role definition
	case roleDefinitionRegex.MatchString(n):
		err = readAndProcessFile(res, file, processRoleDefinition)

	// if the file is an archetype definition
	case archetypeDefinitionRegex.MatchString(n):
		err = readAndProcessFile(res, file, processArchetype)

	// if the file is an archetype override
	case archetypeOverrideRegex.MatchString(n):
		err = readAndProcessFile(res, file, processArchetypeOverride)

	// if the file is an policy default values file
	case policyDefaultValuesRegex.MatchString(n):
		err = readAndProcessFile(res, file, processDefaultPolicyValues)
	}

	// if the file is an architecture definition
	if architectureDefinitionRegex.MatchString(name) {
		err = readAndProcessFile(res, file, processArchitecture)
	}

	if err != nil {
		err = fmt.Errorf("classifyLibFile: error processing file: %w", err)
	}

	return err
}

// processArchitecture is a processFunc that reads the default_policy_values
// bytes, processes, then adds the created processArchitecture to the result.
func processArchitecture(res *Result, unmar unmarshaler) error {
	arch := new(LibArchitecture)
	if err := unmar.unmarshal(arch); err != nil {
		return fmt.Errorf("processArchitecture: error unmarshaling: %w", err)
	}
	if arch.Name == "" {
		return fmt.Errorf("processArchitecture: architecture name is empty")
	}
	if _, exists := res.LibArchitectures[arch.Name]; exists {
		return fmt.Errorf("processArchitecture: architecture with name `%s` already exists", arch.Name)
	}
	res.LibArchitectures[arch.Name] = arch
	return nil
}

// processDefaultPolicyValues is a processFunc that reads the default_policy_values
// bytes, processes, then adds the created LibDefaultPolicyValues to the result.
func processDefaultPolicyValues(res *Result, unmar unmarshaler) error {
	lpv := new(LibDefaultPolicyValues)
	if err := unmar.unmarshal(lpv); err != nil {
		return fmt.Errorf("processDefaultPolicyValues: error unmarshaling: %w", err)
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
// bytes, processes, then adds the created LibArchetype to the result.
func processArchetype(res *Result, unmar unmarshaler) error {
	la := new(LibArchetype)
	if err := unmar.unmarshal(la); err != nil {
		return fmt.Errorf("processArchetype: error unmarshaling: %w", err)
	}
	if _, exists := res.LibArchetypes[la.Name]; exists {
		return fmt.Errorf("processArchetype: archetype with name `%s` already exists", la.Name)
	}
	res.LibArchetypes[la.Name] = la
	return nil
}

// processArchetypeOverride is a processFunc that reads the archetype_override
// bytes, processes, then adds the created LibArchetypeOverride to the result.
func processArchetypeOverride(res *Result, unmar unmarshaler) error {
	lao := new(LibArchetypeOverride)
	if err := unmar.unmarshal(lao); err != nil {
		return fmt.Errorf("processArchetypeOverride: error unmarshaling: %w", err)
	}
	if _, exists := res.LibArchetypeOverrides[lao.Name]; exists {
		return fmt.Errorf("processArchetypeOverride: archetype override with name `%s` already exists", lao.Name)
	}
	res.LibArchetypeOverrides[lao.Name] = lao
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_assignment
// bytes, processes, then adds the created armpolicy.Assignment to the result.
func processPolicyAssignment(res *Result, unmar unmarshaler) error {
	pa := new(armpolicy.Assignment)
	if err := unmar.unmarshal(pa); err != nil {
		return fmt.Errorf("processPolicyAssignment: error unmarshaling: %w", err)
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
func processPolicyDefinition(res *Result, unmar unmarshaler) error {
	pd := new(armpolicy.Definition)
	if err := unmar.unmarshal(pd); err != nil {
		return fmt.Errorf("processPolicyDefinition: error unmarshaling: %w", err)
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
func processPolicySetDefinition(res *Result, unmar unmarshaler) error {
	psd := new(armpolicy.SetDefinition)
	if err := unmar.unmarshal(psd); err != nil {
		return fmt.Errorf("processPolicySetDefinition: error unmarshaling: %w", err)
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
func processRoleDefinition(res *Result, unmar unmarshaler) error {
	rd := new(armauthorization.RoleDefinition)
	if err := unmar.unmarshal(rd); err != nil {
		return fmt.Errorf("processRoleDefinition: error unmarshalling: %w", err)
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

	ext := filepath.Ext(s.Name())
	// create a new unmarshaler
	unmar := newUnmarshaler(data, ext)

	// pass the  data to the supplied process function
	if err := processFn(res, unmar); err != nil {
		return err
	}
	return nil
}
