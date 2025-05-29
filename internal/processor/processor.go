// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package processor

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/internal/environment"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// These are the file prefixes for the resource types.
const (
	architectureDefinitionSuffix = ".+\\.alz_architecture_definition\\.(?:json|yaml|yml)$"
	archetypeDefinitionSuffix    = ".+\\.alz_archetype_definition\\.(?:json|yaml|yml)$"
	archetypeOverrideSuffix      = ".+\\.alz_archetype_override\\.(?:json|yaml|yml)$"
	policyAssignmentSuffix       = ".+\\.alz_policy_assignment\\.(?:json|yaml|yml)$"
	policyDefinitionSuffix       = ".+\\.alz_policy_definition\\.(?:json|yaml|yml)$"
	policySetDefinitionSuffix    = ".+\\.alz_policy_set_definition\\.(?:json|yaml|yml)$"
	roleDefinitionSuffix         = ".+\\.alz_role_definition\\.(?:json|yaml|yml)$"
	policyDefaultValueFileName   = "^alz_policy_default_values\\.(?:json|yaml|yml)$"
)

const (
	alzLibraryMetadataFile = "alz_library_metadata.json"
)

var supportedFileTypes = []string{".json", ".yaml", ".yml"}

var architectureDefinitionRegex = regexp.MustCompile(architectureDefinitionSuffix)
var archetypeDefinitionRegex = regexp.MustCompile(archetypeDefinitionSuffix)
var archetypeOverrideRegex = regexp.MustCompile(archetypeOverrideSuffix)
var policyAssignmentRegex = regexp.MustCompile(policyAssignmentSuffix)
var policyDefinitionRegex = regexp.MustCompile(policyDefinitionSuffix)
var policySetDefinitionRegex = regexp.MustCompile(policySetDefinitionSuffix)
var roleDefinitionRegex = regexp.MustCompile(roleDefinitionSuffix)
var policyDefaultValuesRegex = regexp.MustCompile(policyDefaultValueFileName)

// Result is the structure that gets built by scanning the library files.
type Result struct {
	PolicyDefinitions                   map[string]*armpolicy.Definition
	PolicySetDefinitions                map[string]*armpolicy.SetDefinition
	PolicyAssignments                   map[string]*assets.PolicyAssignment
	RoleDefinitions                     map[string]*armauthorization.RoleDefinition
	LibArchetypes                       map[string]*LibArchetype
	LibArchetypeOverrides               map[string]*LibArchetypeOverride
	LibDefaultPolicyValues              map[string]*LibDefaultPolicyValuesDefaults
	LibArchitectures                    map[string]*LibArchitecture
	Metadata                            *LibMetadata
	libDefaultPolicyValuesFileProcessed bool
}

func NewResult() *Result {
	return &Result{
		PolicyDefinitions:                   make(map[string]*armpolicy.Definition),
		PolicySetDefinitions:                make(map[string]*armpolicy.SetDefinition),
		PolicyAssignments:                   make(map[string]*assets.PolicyAssignment),
		RoleDefinitions:                     make(map[string]*armauthorization.RoleDefinition),
		LibArchetypes:                       make(map[string]*LibArchetype),
		LibArchetypeOverrides:               make(map[string]*LibArchetypeOverride),
		LibDefaultPolicyValues:              make(map[string]*LibDefaultPolicyValuesDefaults),
		LibArchitectures:                    make(map[string]*LibArchitecture),
		Metadata:                            nil,
		libDefaultPolicyValuesFileProcessed: false,
	}
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

// Metadata returns the metadata of the library.
func (client *ProcessorClient) Metadata() (*LibMetadata, error) {
	metadataFile, err := client.fs.Open(alzLibraryMetadataFile)
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return &LibMetadata{
			Name:         "",
			DisplayName:  "",
			Description:  "",
			Path:         "",
			Dependencies: make([]LibMetadataDependency, 0),
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ProcessorClient.Metadata: error opening metadata file: %w", err)
	}
	defer metadataFile.Close() // nolint: errcheck
	data, err := io.ReadAll(metadataFile)
	if err != nil {
		return nil, fmt.Errorf("ProcessorClient.Metadata: error reading metadata file: %w", err)
	}
	unmar := newUnmarshaler(data, ".json")
	metadata := new(LibMetadata)
	err = unmar.unmarshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("ProcessorClient.Metadata: error unmarshaling metadata: %w", err)
	}
	for _, dep := range metadata.Dependencies {
		switch {
		case dep.Path != "" && dep.Ref != "" && dep.CustomUrl == "":
			continue
		case dep.Path == "" && dep.Ref == "" && dep.CustomUrl != "":
			continue
		default:
			return nil, fmt.Errorf("ProcessorClient.Metadata: invalid dependency, either path & ref should be set, or custom_url: %v", dep)
		}
	}
	return metadata, nil
}

// Process reads the library files and processes them into a Result.
// Pass in a pointer to a Result struct to store the processed data,
// create a new *Result with NewResult().
func (client *ProcessorClient) Process(res *Result) error {
	// Open the metadata file and store contents in the result
	metad, err := client.Metadata()
	if err != nil {
		return fmt.Errorf("ProcessorClient.Process: error getting metadata: %w", err)
	}
	res.Metadata = metad

	// Walk the embedded lib FS and process files
	if err := fs.WalkDir(client.fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("ProcessorClient.Process: error walking directory %s: %w", path, err)
		}
		// Skip directories
		if d.IsDir() {
			return nil
		}
		// Skip files where path contains base of the `ALZLIB_DIR`.
		alzLibDirBase := filepath.Base(environment.AlzLibDir())
		if strings.Contains(path, alzLibDirBase) {
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
		err = readAndProcessFile(res, file, processDefaultPolicyValue)
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

// processDefaultPolicyValue is a processFunc that reads the default_policy_value
// bytes, processes, then adds the created LibDefaultPolicyValues to the result.
func processDefaultPolicyValue(res *Result, unmar unmarshaler) error {
	if res.libDefaultPolicyValuesFileProcessed {
		return fmt.Errorf("processDefaultPolicyValues: multiple default policy values files found, only one is allowed")
	}
	lpv := new(LibDefaultPolicyValues)
	if err := unmar.unmarshal(lpv); err != nil {
		return fmt.Errorf("processDefaultPolicyValues: error unmarshaling: %w", err)
	}
	for _, def := range lpv.Defaults {
		if _, exists := res.LibDefaultPolicyValues[def.DefaultName]; exists {
			return fmt.Errorf("processDefaultPolicyValues: default policy values with name `%s` already exists", def.DefaultName)
		}
		res.LibDefaultPolicyValues[def.DefaultName] = &def
	}
	res.libDefaultPolicyValuesFileProcessed = true
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
// bytes, processes, then adds the created assets.PolicyAssignment to the result.
func processPolicyAssignment(res *Result, unmar unmarshaler) error {
	pa := new(assets.PolicyAssignment)
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
// bytes, processes, then adds the created armauthorization.RoleDefinition to the result.
// We use Properties.RoleName as the key in the result map, as the GUID must be unique and a role definition may be deployed at multiple scopes.
func processRoleDefinition(res *Result, unmar unmarshaler) error {
	rd := new(armauthorization.RoleDefinition)
	if err := unmar.unmarshal(rd); err != nil {
		return fmt.Errorf("processRoleDefinition: error unmarshalling: %w", err)
	}
	if rd.Properties == nil || rd.Properties.RoleName == nil || *rd.Properties.RoleName == "" {
		return fmt.Errorf("processRoleDefinition: role definition role name is empty or not present")
	}
	if _, exists := res.RoleDefinitions[*rd.Properties.RoleName]; exists {
		return fmt.Errorf("processRoleDefinition: role definition with role name `%s` already exists", *rd.Properties.RoleName)
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
