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
)

// These are the file prefixes for the resource types.
const (
	PolicyAssignmentFileType       = "alz_policy_assignment"
	PolicyDefinitionFileType       = "alz_policy_definition"
	PolicySetDefinitionFileType    = "alz_policy_set_definition"
	RoleDefinitionFileType         = "alz_role_definition"
	ArchitectureDefinitionFileType = "alz_architecture_definition"
	ArchetypeDefinitionFileType    = "alz_archetype_definition"
	ArchetypeOverrideFileType      = "alz_archetype_override"
	PolicyDefaultValuesFileType    = "alz_policy_default_values"
	architectureDefinitionSuffix   = ".+\\." + ArchitectureDefinitionFileType + "\\.(?:json|yaml|yml)$"
	archetypeDefinitionSuffix      = ".+\\." + ArchetypeDefinitionFileType + "\\.(?:json|yaml|yml)$"
	archetypeOverrideSuffix        = ".+\\." + ArchetypeOverrideFileType + "\\.(?:json|yaml|yml)$"
	policyAssignmentSuffix         = ".+\\." + PolicyAssignmentFileType + "\\.(?:json|yaml|yml)$"
	policyDefinitionSuffix         = ".+\\." + PolicyDefinitionFileType + "\\.(?:json|yaml|yml)$"
	policySetDefinitionSuffix      = ".+\\." + PolicySetDefinitionFileType + "\\.(?:json|yaml|yml)$"
	roleDefinitionSuffix           = ".+\\." + RoleDefinitionFileType + "\\.(?:json|yaml|yml)$"
	policyDefaultValueFileName     = "^" + PolicyDefaultValuesFileType + "\\.(?:json|yaml|yml)$"
)

const (
	alzLibraryMetadataFile = "alz_library_metadata.json"
)

var supportedFileTypes = []string{".json", ".yaml", ".yml"}

var ArchitectureDefinitionRegex = regexp.MustCompile(architectureDefinitionSuffix)
var ArchetypeDefinitionRegex = regexp.MustCompile(archetypeDefinitionSuffix)
var ArchetypeOverrideRegex = regexp.MustCompile(archetypeOverrideSuffix)
var PolicyAssignmentRegex = regexp.MustCompile(policyAssignmentSuffix)
var PolicyDefinitionRegex = regexp.MustCompile(policyDefinitionSuffix)
var PolicySetDefinitionRegex = regexp.MustCompile(policySetDefinitionSuffix)
var RoleDefinitionRegex = regexp.MustCompile(roleDefinitionSuffix)
var PolicyDefaultValuesRegex = regexp.MustCompile(policyDefaultValueFileName)

var (
	// ErrResourceAlreadyExists is returned when a resource already exists in the result.
	ErrResourceAlreadyExists = errors.New("resource already exists in the result")

	// ErrNoNameProvided is returned when no name was provided for the resource.
	ErrNoNameProvided = errors.New("no name provided for the resource, cannot process it without a name")

	// ErrUnmarshaling is returned when unmarshaling fails.
	ErrUnmarshaling = errors.New("error converting data from YAML/JSON, please check the file format and content")

	// ErrMultipleDefaultPolicyValuesFileFound is returned when multiple default policy values files are found.
	ErrMultipleDefaultPolicyValuesFileFound = errors.New("multiple default policy values files found, only one is allowed")

	// ErrProcessingFile is returned when there is an error processing the file.
	ErrProcessingFile = errors.New("error processing file, please check the file format and content")
)

// NewErrResourceAlreadyExists creates a new error indicating that a resource already exists in the result.
func NewErrResourceAlreadyExists(resourceType, name string) error {
	return fmt.Errorf("%w: %s with name `%s` already exists", ErrResourceAlreadyExists, resourceType, name)
}

// NewErrNoNameProvided creates a new error indicating that no name was provided for the resource.
func NewErrNoNameProvided(resourceType string) error {
	return fmt.Errorf("%w: %s", ErrNoNameProvided, resourceType)
}

// NewErrorUnmarshaling creates a new error indicating that unmarshaling failed.
func NewErrorUnmarshaling(detail string) error {
	return fmt.Errorf("%w: %s", ErrUnmarshaling, detail)
}

// Result is the structure that gets built by scanning the library files.
type Result struct {
	PolicyDefinitions                   map[string]*assets.PolicyDefinitionVersions
	PolicySetDefinitions                map[string]*assets.PolicySetDefinitionVersions
	PolicyAssignments                   map[string]*assets.PolicyAssignment
	RoleDefinitions                     map[string]*assets.RoleDefinition
	LibArchetypes                       map[string]*LibArchetype
	LibArchetypeOverrides               map[string]*LibArchetypeOverride
	LibDefaultPolicyValues              map[string]*LibDefaultPolicyValuesDefaults
	LibArchitectures                    map[string]*LibArchitecture
	Metadata                            *LibMetadata
	libDefaultPolicyValuesFileProcessed bool
}

// NewResult creates a new Result struct with initialized maps for each resource type.
func NewResult() *Result {
	return &Result{
		PolicyDefinitions:                   make(map[string]*assets.PolicyDefinitionVersions),
		PolicySetDefinitions:                make(map[string]*assets.PolicySetDefinitionVersions),
		PolicyAssignments:                   make(map[string]*assets.PolicyAssignment),
		RoleDefinitions:                     make(map[string]*assets.RoleDefinition),
		LibArchetypes:                       make(map[string]*LibArchetype),
		LibArchetypeOverrides:               make(map[string]*LibArchetypeOverride),
		LibDefaultPolicyValues:              make(map[string]*LibDefaultPolicyValuesDefaults),
		LibArchitectures:                    make(map[string]*LibArchitecture),
		Metadata:                            nil,
		libDefaultPolicyValuesFileProcessed: false,
	}
}

// processFunc is the function signature that is used to process different types of lib file.
type processFunc func(result *Result, data Unmarshaler) error

// Client is the client that is used to process the library files.
type Client struct {
	fs fs.FS
}

// NewClient creates a new Client with the provided filesystem.
func NewClient(fs fs.FS) *Client {
	return &Client{
		fs: fs,
	}
}

// Metadata returns the metadata of the library.
func (client *Client) Metadata() (*LibMetadata, error) {
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

	unmar := NewUnmarshaler(data, ".json")
	metadata := new(LibMetadata)

	err = unmar.Unmarshal(metadata)
	if err != nil {
		return nil, errors.Join(NewErrorUnmarshaling(alzLibraryMetadataFile), err)
	}

	for _, dep := range metadata.Dependencies {
		switch {
		case dep.Path != "" && dep.Ref != "" && dep.CustomURL == "":
			continue
		case dep.Path == "" && dep.Ref == "" && dep.CustomURL != "":
			continue
		default:
			return nil, fmt.Errorf(
				"ProcessorClient.Metadata: invalid dependency, either path & ref should be set, or custom_url: %v",
				dep,
			)
		}
	}

	return metadata, nil
}

// Process reads the library files and processes them into a Result.
// Pass in a pointer to a Result struct to store the processed data,
// create a new *Result with NewResult().
func (client *Client) Process(res *Result) error {
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
		return err //nolint:wrapcheck
	}

	return nil
}

// classifyLibFile identifies the supplied file and adds calls the appropriate processFunc.
func classifyLibFile(res *Result, file fs.File, name string) error {
	err := error(nil)

	// process by file type
	switch n := strings.ToLower(name); {
	// if the file is a policy definition
	case PolicyDefinitionRegex.MatchString(n):
		err = readAndProcessFile(res, file, processPolicyDefinition)

	// if the file is a policy set definition
	case PolicySetDefinitionRegex.MatchString(n):
		err = readAndProcessFile(res, file, processPolicySetDefinition)

	// if the file is a policy assignment
	case PolicyAssignmentRegex.MatchString(n):
		err = readAndProcessFile(res, file, processPolicyAssignment)

	// if the file is a role definition
	case RoleDefinitionRegex.MatchString(n):
		err = readAndProcessFile(res, file, processRoleDefinition)

	// if the file is an archetype definition
	case ArchetypeDefinitionRegex.MatchString(n):
		err = readAndProcessFile(res, file, processArchetype)

	// if the file is an archetype override
	case ArchetypeOverrideRegex.MatchString(n):
		err = readAndProcessFile(res, file, processArchetypeOverride)

	// if the file is an policy default values file
	case PolicyDefaultValuesRegex.MatchString(n):
		err = readAndProcessFile(res, file, processDefaultPolicyValue)

		// if the file is an architecture definition
	case ArchitectureDefinitionRegex.MatchString(n):
		err = readAndProcessFile(res, file, processArchitecture)
	}

	if err != nil {
		err = errors.Join(
			ErrProcessingFile, err,
		)
	}

	return err
}

// processArchitecture is a processFunc that reads the default_policy_values
// bytes, processes, then adds the created processArchitecture to the result.
func processArchitecture(res *Result, unmar Unmarshaler) error {
	arch := new(LibArchitecture)
	if err := unmar.Unmarshal(arch); err != nil {
		return errors.Join(NewErrorUnmarshaling("architecture definition"), err)
	}

	if arch.Name == "" {
		return NewErrNoNameProvided("architecture")
	}

	if _, exists := res.LibArchitectures[arch.Name]; exists {
		return NewErrResourceAlreadyExists("architecture", arch.Name)
	}

	res.LibArchitectures[arch.Name] = arch

	return nil
}

// processDefaultPolicyValue is a processFunc that reads the default_policy_value
// bytes, processes, then adds the created LibDefaultPolicyValues to the result.
func processDefaultPolicyValue(res *Result, unmar Unmarshaler) error {
	if res.libDefaultPolicyValuesFileProcessed {
		return ErrMultipleDefaultPolicyValuesFileFound
	}

	lpv := new(LibDefaultPolicyValues)
	if err := unmar.Unmarshal(lpv); err != nil {
		return errors.Join(NewErrorUnmarshaling("default policy values"), err)
	}

	for _, def := range lpv.Defaults {
		if _, exists := res.LibDefaultPolicyValues[def.DefaultName]; exists {
			return NewErrResourceAlreadyExists("default policy value", def.DefaultName)
		}

		res.LibDefaultPolicyValues[def.DefaultName] = &def
	}

	res.libDefaultPolicyValuesFileProcessed = true

	return nil
}

// processArchetype is a processFunc that reads the archetype_definition
// bytes, processes, then adds the created LibArchetype to the result.
func processArchetype(res *Result, unmar Unmarshaler) error {
	la := new(LibArchetype)
	if err := unmar.Unmarshal(la); err != nil {
		return errors.Join(NewErrorUnmarshaling("archetype definition"), err)
	}

	if _, exists := res.LibArchetypes[la.Name]; exists {
		return NewErrResourceAlreadyExists("archetype", la.Name)
	}

	res.LibArchetypes[la.Name] = la

	return nil
}

// processArchetypeOverride is a processFunc that reads the archetype_override
// bytes, processes, then adds the created LibArchetypeOverride to the result.
func processArchetypeOverride(res *Result, unmar Unmarshaler) error {
	lao := new(LibArchetypeOverride)
	if err := unmar.Unmarshal(lao); err != nil {
		return errors.Join(NewErrorUnmarshaling("archetype override"), err)
	}

	if _, exists := res.LibArchetypeOverrides[lao.Name]; exists {
		return NewErrResourceAlreadyExists("archetype override", lao.Name)
	}

	res.LibArchetypeOverrides[lao.Name] = lao

	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_assignment
// bytes, processes, then adds the created assets.PolicyAssignment to the result.
func processPolicyAssignment(res *Result, unmar Unmarshaler) error {
	pa := new(assets.PolicyAssignment)
	if err := unmar.Unmarshal(pa); err != nil {
		return errors.Join(NewErrorUnmarshaling("policy assignment"), err)
	}

	if pa.Name == nil || *pa.Name == "" {
		return NewErrNoNameProvided("policy assignment")
	}

	if _, exists := res.PolicyAssignments[*pa.Name]; exists {
		return NewErrResourceAlreadyExists("policy assignment", *pa.Name)
	}

	res.PolicyAssignments[*pa.Name] = pa

	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_definition
// bytes, processes, then adds the created assets.PolicyDefinition to the result.
func processPolicyDefinition(res *Result, unmar Unmarshaler) error {
	pd := new(assets.PolicyDefinition)
	if err := unmar.Unmarshal(pd); err != nil {
		return errors.Join(NewErrorUnmarshaling("policy definition"), err)
	}

	if pd.Name == nil || *pd.Name == "" {
		return NewErrNoNameProvided("policy definition")
	}

	if pdv, exists := res.PolicyDefinitions[*pd.Name]; exists {
		if pdv.Exists(pd.GetVersion()) {
			ver := "(no version)"
			if pd.GetVersion() != nil {
				ver = *pd.GetVersion()
			}

			return NewErrResourceAlreadyExists(
				"policy definition (version)", fmt.Sprintf("%s for %s already exists",
					ver,
					*pd.Name,
				),
			)
		}
	}

	if _, ok := res.PolicyDefinitions[*pd.Name]; !ok {
		res.PolicyDefinitions[*pd.Name] = assets.NewPolicyDefinitionVersions()
	}

	if err := res.PolicyDefinitions[*pd.Name].Add(pd, false); err != nil {
		return errors.Join(
			errors.New("processPolicyDefinition: error adding policy definition to collection"),
			err,
		)
	}

	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_set_definition
// bytes, processes, then adds the created assets.PolicySetDefinition to the result.
func processPolicySetDefinition(res *Result, unmar Unmarshaler) error {
	psd := new(assets.PolicySetDefinition)
	if err := unmar.Unmarshal(psd); err != nil {
		return errors.Join(NewErrorUnmarshaling("policy set definition"), err)
	}

	if psd.Name == nil || *psd.Name == "" {
		return NewErrNoNameProvided("policy set definition")
	}

	if psdv, exists := res.PolicySetDefinitions[*psd.Name]; exists {
		if psdv.Exists(psd.GetVersion()) {
			ver := "(no version)"
			if psd.GetVersion() != nil {
				ver = *psd.GetVersion()
			}

			return NewErrResourceAlreadyExists(
				"policy set definition (version)", fmt.Sprintf("%s for %s already exists",
					ver,
					*psd.Name),
			)
		}
	}

	if _, ok := res.PolicySetDefinitions[*psd.Name]; !ok {
		res.PolicySetDefinitions[*psd.Name] = assets.NewPolicySetDefinitionVersions()
	}

	if err := res.PolicySetDefinitions[*psd.Name].Add(psd, false); err != nil {
		return errors.Join(
			errors.New("processPolicySetDefinition: error adding policy set definition to collection"),
			err,
		)
	}

	return nil
}

// processRoleDefinition is a processFunc that reads the role_definition
// bytes, processes, then adds the created armauthorization.RoleDefinition to the result.
// We use Properties.RoleName as the key in the result map, as the GUID must be unique and a role
// definition may be
// deployed at multiple scopes.
func processRoleDefinition(res *Result, unmar Unmarshaler) error {
	rd := new(assets.RoleDefinition)
	if err := unmar.Unmarshal(rd); err != nil {
		return errors.Join(NewErrorUnmarshaling("role definition"), err)
	}

	if rd.Properties == nil || rd.Properties.RoleName == nil || *rd.Properties.RoleName == "" {
		return NewErrNoNameProvided("role definition")
	}

	if _, exists := res.RoleDefinitions[*rd.Properties.RoleName]; exists {
		return NewErrResourceAlreadyExists("role definition", *rd.Properties.RoleName)
	}
	// Use roleName here not the name, which is a GUID
	res.RoleDefinitions[*rd.Properties.RoleName] = rd

	return nil
}

// readAndProcessFile reads the file bytes at the supplied path and processes it using the supplied
// processFunc.
func readAndProcessFile(res *Result, file fs.File, processFn processFunc) error {
	s, err := file.Stat()
	if err != nil {
		return err //nolint:wrapcheck
	}

	data := make([]byte, s.Size())

	defer file.Close() // nolint:errcheck

	if _, err := file.Read(data); err != nil {
		return err //nolint:wrapcheck
	}

	ext := filepath.Ext(s.Name())
	// create a new unmarshaler
	unmar := NewUnmarshaler(data, ext)

	// pass the  data to the supplied process function
	if err := processFn(res, unmar); err != nil {
		return err //nolint:wrapcheck
	}

	return nil
}
