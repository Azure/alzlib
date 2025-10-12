// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/internal/processor"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/brunoga/deep"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/hashicorp/go-multierror"
)

const (
	defaultParallelism           = 10 // default number of parallel requests to make to Azure APIs
	defaultOverwrite             = false
	defaultUniqueRoleDefinitions = true // default to unique role definitions per management group
	// InitialMetadataSliceCapacity is the initial capacity for the metadata slice.
	InitialMetadataSliceCapacity = 10
	// MaxRecursionDepth is the maximum depth for recursive operations.
	MaxRecursionDepth = 5
)

// AlzLib is the structure that gets built from the the library files
// do not create this directly, use NewAlzLib instead.
type AlzLib struct {
	Options *Options

	archetypes                    map[string]*Archetype
	architectures                 map[string]*Architecture
	policyAssignments             map[string]*assets.PolicyAssignment
	policyDefinitions             map[string]*assets.PolicyDefinitionVersions
	policySetDefinitions          map[string]*assets.PolicySetDefinitionVersions
	roleDefinitions               map[string]*assets.RoleDefinition
	defaultPolicyAssignmentValues DefaultPolicyAssignmentValues
	metadata                      []*Metadata

	clients *azureClients
	mu      sync.RWMutex // mu is a mutex to concurrency protect the AlzLib maps
}

type azureClients struct {
	policyClient *armpolicy.ClientFactory
}

// Options are options for the AlzLib.
type Options struct {
	// AllowOverwrite allows overwriting of existing policy assignments when processing additional libraries
	// with AlzLib.Init().
	AllowOverwrite bool
	// Parallelism is the number of parallel requests to make to Azure APIs when getting policy definitions
	// and policy set definitions.
	Parallelism int
	// UniqueRoleDefinitions indicates whether to update the role definitions to be unique per management group.
	// If this is not set, you may end up with conflicting role definition names.
	UniqueRoleDefinitions bool
}

// NewAlzLib returns a new instance of the alzlib library, optionally using the supplied directory
// for additional policy (set) definitions.
// To customize the options for the AlzLib, pass in an AlzLibOptions struct, otherwise the default
// options will be used.
func NewAlzLib(opts *Options) *AlzLib {
	if opts == nil {
		opts = defaultAlzLibOptions()
	}

	az := &AlzLib{
		Options:                       opts,
		archetypes:                    make(map[string]*Archetype),
		architectures:                 make(map[string]*Architecture),
		policyAssignments:             make(map[string]*assets.PolicyAssignment),
		policyDefinitions:             make(map[string]*assets.PolicyDefinitionVersions),
		policySetDefinitions:          make(map[string]*assets.PolicySetDefinitionVersions),
		roleDefinitions:               make(map[string]*assets.RoleDefinition),
		metadata:                      make([]*Metadata, 0, InitialMetadataSliceCapacity),
		defaultPolicyAssignmentValues: make(DefaultPolicyAssignmentValues),
		clients:                       new(azureClients),
		mu:                            sync.RWMutex{},
	}

	return az
}

func defaultAlzLibOptions() *Options {
	return &Options{
		Parallelism:           defaultParallelism,
		AllowOverwrite:        defaultOverwrite,
		UniqueRoleDefinitions: defaultUniqueRoleDefinitions,
	}
}

// Metadata returns all the registered metadata in the AlzLib struct.
func (az *AlzLib) Metadata() []*Metadata {
	az.mu.RLock()
	defer az.mu.RUnlock()

	return deep.MustCopy(az.metadata)
}

// AddPolicyAssignments adds policy assignments to the AlzLib struct.
func (az *AlzLib) AddPolicyAssignments(pas ...*assets.PolicyAssignment) error {
	az.mu.Lock()
	defer az.mu.Unlock()

	for _, pa := range pas {
		if pa == nil || pa.Name == nil || *pa.Name == "" {
			continue
		}

		if _, exists := az.policyAssignments[*pa.Name]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf(
				"Alzlib.AddPolicyAssignments: policy assignment with name %s already exists and allow overwrite not set",
				*pa.Name,
			)
		}

		cpy, err := deep.Copy(pa)
		if err != nil {
			return fmt.Errorf(
				"Alzlib.AddPolicyAssignments: error making deep copy of policy assignment %s: %w",
				*pa.Name,
				err,
			)
		}

		az.policyAssignments[*pa.Name] = cpy
	}

	return nil
}

// AddPolicyDefinitions adds policy definitions to the AlzLib struct.
func (az *AlzLib) AddPolicyDefinitions(pds ...*assets.PolicyDefinition) error {
	az.mu.Lock()
	defer az.mu.Unlock()

	var merr error

	for _, pd := range pds {
		if pd == nil || pd.Name == nil || *pd.Name == "" {
			continue
		}

		if pdvc, exists := az.policyDefinitions[*pd.Name]; exists {
			if err := pdvc.Add(pd, az.Options.AllowOverwrite); err != nil {
				merr = multierror.Append(merr, pdvc.Upsert(pdvc, az.Options.AllowOverwrite))
			}

			continue
		}

		cpy := deep.MustCopy(pd)
		pdvc := assets.NewPolicyDefinitionVersions()
		pdvc.Add(cpy, az.Options.AllowOverwrite) // nolint:errcheck
		az.policyDefinitions[*pd.Name] = pdvc
	}

	return merr
}

// AddPolicySetDefinitions adds policy set definitions to the AlzLib struct.
func (az *AlzLib) AddPolicySetDefinitions(psds ...*assets.PolicySetDefinition) error {
	az.mu.Lock()
	defer az.mu.Unlock()

	var merr error

	for _, psd := range psds {
		if psd == nil || psd.Name == nil || *psd.Name == "" {
			continue
		}

		if psdvc, exists := az.policySetDefinitions[*psd.Name]; exists {
			if err := psdvc.Add(psd, az.Options.AllowOverwrite); err != nil {
				merr = multierror.Append(merr, err)
			}

			continue
		}

		cpy := deep.MustCopy(psd)
		psdvc := assets.NewPolicySetDefinitionVersions()
		psdvc.Add(cpy, az.Options.AllowOverwrite) // nolint:errcheck
		az.policySetDefinitions[*psd.Name] = psdvc
	}

	return merr
}

// AddRoleDefinitions adds role definitions to the AlzLib struct.
func (az *AlzLib) AddRoleDefinitions(rds ...*assets.RoleDefinition) error {
	az.mu.Lock()
	defer az.mu.Unlock()

	for _, rd := range rds {
		if rd == nil || rd.Name == nil || *rd.Name == "" {
			continue
		}

		if _, exists := az.roleDefinitions[*rd.Name]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf(
				"Alzlib.AddRoleDefinitions: role definition with name %s already exists and allow overwrite not set",
				*rd.Name,
			)
		}

		cpy, err := deep.Copy(rd)
		if err != nil {
			return fmt.Errorf(
				"Alzlib.AddRoleDefinitions: error making deep copy of role definition %s: %w",
				*rd.Name,
				err,
			)
		}

		az.roleDefinitions[*rd.Name] = cpy
	}

	return nil
}

// PolicyAssignments returns a slice of all the policy assignment names in the library.
func (az *AlzLib) PolicyAssignments() []string {
	az.mu.RLock()
	defer az.mu.RUnlock()

	result := make([]string, 0, len(az.policyAssignments))
	for k := range az.policyAssignments {
		result = append(result, k)
	}

	slices.Sort(result)

	return result
}

// PolicyDefinitions returns a slice of all the policy definition names in the library.
func (az *AlzLib) PolicyDefinitions() []string {
	az.mu.RLock()
	defer az.mu.RUnlock()

	result := make([]string, 0, len(az.policyDefinitions))
	for k := range az.policyDefinitions {
		result = append(result, k)
	}

	slices.Sort(result)

	return result
}

// PolicySetDefinitions returns a slice of all the policy set definition names in the library.
func (az *AlzLib) PolicySetDefinitions() []string {
	az.mu.RLock()
	defer az.mu.RUnlock()

	result := make([]string, 0, len(az.policySetDefinitions))
	for k := range az.policySetDefinitions {
		result = append(result, k)
	}

	slices.Sort(result)

	return result
}

// RoleDefinitions returns a slice of all the role definition names in the library.
func (az *AlzLib) RoleDefinitions() []string {
	az.mu.RLock()
	defer az.mu.RUnlock()

	result := make([]string, 0, len(az.roleDefinitions))
	for k := range az.roleDefinitions {
		result = append(result, k)
	}

	slices.Sort(result)

	return result
}

// Archetypes returns a list of the archetypes in the AlzLib struct.
func (az *AlzLib) Archetypes() []string {
	az.mu.RLock()
	defer az.mu.RUnlock()

	result := make([]string, 0, len(az.archetypes))
	for k := range az.archetypes {
		result = append(result, k)
	}

	slices.Sort(result)

	return result
}

// Archetype returns a copy of the requested archetype by name.
func (az *AlzLib) Archetype(name string) *Archetype {
	az.mu.RLock()
	defer az.mu.RUnlock()

	arch, ok := az.archetypes[name]
	if !ok {
		return nil
	}

	return arch.copy()
}

// Architectures returns a list of the architecture names in the AlzLib struct.
func (az *AlzLib) Architectures() []string {
	az.mu.RLock()
	defer az.mu.RUnlock()

	result := make([]string, 0, len(az.architectures))
	for k := range az.architectures {
		result = append(result, k)
	}

	slices.Sort(result)

	return result
}

// PolicyDefaultValues returns a sorted list of the default policy assignment default values in the
// AlzLib struct.
func (az *AlzLib) PolicyDefaultValues() []string {
	az.mu.RLock()
	defer az.mu.RUnlock()

	result := make([]string, 0, len(az.defaultPolicyAssignmentValues))
	for k := range az.defaultPolicyAssignmentValues {
		result = append(result, k)
	}

	slices.Sort(result)

	return result
}

// PolicyDefaultValue returns a copy of the requested default policy assignment default values by name.
func (az *AlzLib) PolicyDefaultValue(name string) *DefaultPolicyAssignmentValuesValue {
	az.mu.RLock()
	defer az.mu.RUnlock()

	val, ok := az.defaultPolicyAssignmentValues[name]
	if !ok {
		return nil
	}

	ret := val.copy()

	return &ret
}

// Architecture returns the requested architecture.
func (az *AlzLib) Architecture(name string) *Architecture {
	az.mu.RLock()
	defer az.mu.RUnlock()

	arch, ok := az.architectures[name]
	if !ok {
		return nil
	}

	return arch
}

// PolicyDefinitionExists returns true if the policy definition name exists in the AlzLib struct.
func (az *AlzLib) PolicyDefinitionExists(name string, version *string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()

	pdvc, exists := az.policyDefinitions[name]
	if !exists {
		return false
	}

	pdv, err := pdvc.GetVersion(version)
	if err != nil {
		return false
	}

	return pdv != nil
}

// PolicySetDefinitionExists returns true if the policy set definition name and version exists in the AlzLib
// struct.
func (az *AlzLib) PolicySetDefinitionExists(name string, version *string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()

	psdvc, exists := az.policySetDefinitions[name]
	if !exists {
		return false
	}

	psdv, err := psdvc.GetVersion(version)
	if err != nil {
		return false
	}

	return psdv != nil
}

// PolicyAssignmentExists returns true if the policy assignment exists name in the AlzLib struct.
func (az *AlzLib) PolicyAssignmentExists(name string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()

	_, exists := az.policyAssignments[name]

	return exists
}

// RoleDefinitionExists returns true if the role definition name exists in the AlzLib struct.
func (az *AlzLib) RoleDefinitionExists(name string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()

	_, exists := az.roleDefinitions[name]

	return exists
}

// PolicyDefinition returns a deep copy of the requested policy definition version.
// This is safe to modify without affecting the original.
func (az *AlzLib) PolicyDefinition(name string, version *string) *assets.PolicyDefinition {
	az.mu.RLock()
	defer az.mu.RUnlock()

	pd, ok := az.policyDefinitions[name]
	if !ok {
		return nil
	}

	pdv, err := pd.GetVersion(version)
	if err != nil {
		return nil
	}

	return deep.MustCopy(pdv)
}

// SetAssignPermissionsOnDefinitionParameter sets the AssignPermissions metadata field to true for
// the definition and parameter with the given name.
func (az *AlzLib) SetAssignPermissionsOnDefinitionParameter(definitionName string, definitionVersion *string, parameterName string) {
	az.mu.Lock()
	defer az.mu.Unlock()

	definition, ok := az.policyDefinitions[definitionName]
	if !ok {
		return
	}

	pd, err := definition.GetVersionStrict(definitionVersion)
	if err != nil {
		return
	}

	pd.SetAssignPermissionsOnParameter(parameterName)
}

// UnsetAssignPermissionsOnDefinitionParameter removes the AssignPermissions metadata field to true
// for the definition
// and parameter with the given name.
func (az *AlzLib) UnsetAssignPermissionsOnDefinitionParameter(
	definitionName string, definitionVersion *string, parameterName string,
) {
	az.mu.Lock()
	defer az.mu.Unlock()

	definition, ok := az.policyDefinitions[definitionName]
	if !ok {
		return
	}

	pd, err := definition.GetVersionStrict(definitionVersion)
	if err != nil {
		return
	}

	pd.UnsetAssignPermissionsOnParameter(parameterName)
}

// PolicyAssignment returns a deep copy of the requested policy assignment.
// This is safe to modify without affecting the original.
func (az *AlzLib) PolicyAssignment(name string) *assets.PolicyAssignment {
	az.mu.RLock()
	defer az.mu.RUnlock()

	pa, ok := az.policyAssignments[name]
	if !ok {
		return nil
	}

	return deep.MustCopy(pa)
}

// PolicySetDefinition returns a deep copy of the requested policy set definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) PolicySetDefinition(name string, version *string) *assets.PolicySetDefinition {
	az.mu.RLock()
	defer az.mu.RUnlock()

	psd, ok := az.policySetDefinitions[name]
	if !ok {
		return nil
	}

	psdv, err := psd.GetVersion(version)
	if err != nil {
		return nil
	}

	return deep.MustCopy(psdv)
}

// RoleDefinition returns a deep copy of the requested role definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) RoleDefinition(name string) *assets.RoleDefinition {
	az.mu.RLock()
	defer az.mu.RUnlock()

	rd, ok := az.roleDefinitions[name]
	if !ok {
		return nil
	}

	return deep.MustCopy(rd)
}

// AddPolicyClient adds an authenticated *armpolicy.ClientFactory to the AlzLib struct.
// This is needed to get policy objects from Azure.
func (az *AlzLib) AddPolicyClient(client *armpolicy.ClientFactory) {
	az.mu.Lock()
	defer az.mu.Unlock()

	az.clients.policyClient = client
}

// Init processes ALZ libraries, supplied as `LibraryReference` interfaces.
// Use FetchAzureLandingZonesLibraryMember/FetchLibraryByGetterString to get the library from
// GitHub.
// It populates the struct with the results of the processing.
func (az *AlzLib) Init(ctx context.Context, libs ...LibraryReference) error {
	az.mu.Lock()
	defer az.mu.Unlock()

	if az.Options == nil || az.Options.Parallelism == 0 {
		return errors.New("Alzlib.Init: alzlib Options not set or parallelism is `0`")
	}

	// Process the libraries
	for _, ref := range libs {
		if ref == nil {
			return errors.New("Alzlib.Init: library is nil")
		}

		if ref.FS() == nil {
			if _, err := ref.Fetch(ctx, hash(ref)); err != nil {
				return fmt.Errorf("Alzlib.Init: error fetching library %s: %w", ref, err)
			}
		}

		res := processor.NewResult()
		pc := processor.NewClient(ref.FS())

		if err := pc.Process(res); err != nil {
			return fmt.Errorf("Alzlib.Init: error processing library %v: %w", ref, err)
		}

		if res.Metadata != nil {
			az.metadata = append(az.metadata, NewMetadata(res.Metadata, ref))
		}

		// Put results into the AlzLib.
		if err := az.addPolicyAndRoleAssets(res); err != nil {
			return fmt.Errorf("Alzlib.Init: error adding processed result to AlzLib: %w", err)
		}

		// Add default policy values
		if err := az.addDefaultPolicyAssignmentValues(res); err != nil {
			return fmt.Errorf(
				"Alzlib.Init: error adding default policy assignment values to AlzLib: %w",
				err,
			)
		}

		// Generate archetypes
		if err := az.generateArchetypes(res); err != nil {
			return fmt.Errorf("Alzlib.Init: error generating archetypes: %w", err)
		}

		// Generate override archetypes
		if err := az.generateOverrideArchetypes(res); err != nil {
			return fmt.Errorf("Alzlib.Init: error generating override archetypes: %w", err)
		}

		// Generate architectures
		if err := az.generateArchitectures(res); err != nil {
			return fmt.Errorf("Alzlib.Init: error generating architectures: %w", err)
		}
	}

	return nil
}

// GetDefinitionsFromAzure takes a slice of requests for built-in definitions.
// It then fetches them from Azure if they don't already exist (determined by last segment of
// resource id). For set definitions we need to get all of them, even if they exist in AlzLib
// already because they can contain built-in definitions.
func (az *AlzLib) GetDefinitionsFromAzure(ctx context.Context, reqs []BuiltInRequest) error {
	policyDefsToGet := make([]BuiltInRequest, 0, len(reqs))
	policySetDefsToGet := make([]BuiltInRequest, 0, len(reqs))

	for _, req := range reqs {
		if req.ResourceID == nil {
			return fmt.Errorf("Alzlib.GetDefinitionsFromAzure: resource ID is nil in BuiltInRequest")
		}

		switch strings.ToLower(req.ResourceID.ResourceType.Type) {
		case "policydefinitions":
			if !az.PolicyDefinitionExists(req.ResourceID.Name, req.Version) {
				policyDefsToGet = append(policyDefsToGet, req)
			}
		case "policysetdefinitions":
			// If the set is not present, OR if the set contains referenced definitions that are not
			// present add it to the list of set defs to get.
			exists := az.PolicySetDefinitionExists(req.ResourceID.Name, req.Version)
			if !exists {
				policySetDefsToGet = append(policySetDefsToGet, req)
				continue
			}

			psd := az.PolicySetDefinition(req.ResourceID.Name, req.Version)
			if psd == nil {
				version := "<nil>"
				if req.Version != nil {
					version = *req.Version
				}

				return fmt.Errorf(
					"Alzlib.GetDefinitionsFromAzure: error getting policy set definition %s@%s",
					req.ResourceID,
					version,
				)
			}

			// This is already made safe to access by the constructor.
			pdrefs := psd.Properties.PolicyDefinitions

			for _, ref := range pdrefs {
				subResID, err := arm.ParseResourceID(*ref.PolicyDefinitionID)
				if err != nil {
					return fmt.Errorf(
						"Alzlib.GetDefinitionsFromAzure: policy set definition %s error parsing referenced definition resource id: %w",
						*psd.Name,
						err,
					)
				}

				if !az.PolicyDefinitionExists(subResID.Name, ref.DefinitionVersion) {
					subReq := BuiltInRequest{
						ResourceID: subResID,
						Version:    ref.DefinitionVersion,
					}
					policyDefsToGet = append(policyDefsToGet, subReq)
				}
			}

		default:
			return fmt.Errorf(
				"Alzlib.GetDefinitionsFromAzure: unexpected policy definition type when processing assignments: %s",
				req,
			)
		}
	}

	// Add the referenced built-in definitions and set definitions to the AlzLib struct
	// so that we can use the data to determine the correct role assignments at scope.
	if len(policyDefsToGet) != 0 {
		if err := az.getBuiltInPolicies(ctx, policyDefsToGet); err != nil {
			return fmt.Errorf(
				"Alzlib.GetDefinitionsFromAzure: error getting built-in policy definitions: %w",
				err,
			)
		}
	}

	if len(policySetDefsToGet) != 0 {
		if err := az.getBuiltInPolicySets(ctx, policySetDefsToGet); err != nil {
			return fmt.Errorf(
				"Alzlib.GetDefinitionsFromAzure: error getting built-in policy set definitions: %w",
				err,
			)
		}
	}

	return nil
}

// AssignmentReferencedDefinitionHasParameter checks if the referenced definition of an assignment
// has a specific parameter. It takes a resource ID and a parameter name as input and returns a
// boolean indicating whether the parameter exists or not.
func (az *AlzLib) AssignmentReferencedDefinitionHasParameter(
	res *arm.ResourceID,
	definitionVersion *string,
	param string,
) bool {
	switch strings.ToLower(res.ResourceType.Type) {
	case "policydefinitions":
		pd := az.PolicyDefinition(res.Name, definitionVersion)
		if pd == nil {
			// If we don't have the definition, return true as this won't cause an issue.
			// We might be checking that a policy default value exists for a definition that isn't assigned.
			return true
		}

		if pd.Parameter(param) != nil {
			return true
		}
	case "policysetdefinitions":
		psd := az.PolicySetDefinition(res.Name, definitionVersion)
		if psd == nil {
			// If we don't have the definition, return true as this won't cause an issue.
			// We might be checking that a policy default value exists for a definition that isn't assigned.
			return true
		}

		if psd.Parameter(param) != nil {
			return true
		}
	}

	return false
}

// policyDefinitionVersionsPager exposes the subset of pager behaviour needed for testing.
type policyDefinitionVersionsPager interface {
	More() bool
	NextPage(context.Context) (armpolicy.DefinitionVersionsClientListBuiltInResponse, error)
}

// policySetDefinitionVersionsPager exposes the subset of pager behaviour needed for testing.
type policySetDefinitionVersionsPager interface {
	More() bool
	NextPage(context.Context) (armpolicy.SetDefinitionVersionsClientListBuiltInResponse, error)
}

// getBuiltInPolicies retrieves the built-in policy definitions with the given names
// and adds them to the AlzLib struct.
func (az *AlzLib) getBuiltInPolicies(ctx context.Context, reqs []BuiltInRequest) error {
	if az.clients.policyClient == nil {
		return errors.New("Alzlib.getBuiltInPolicies: policy client not set")
	}

	versionedClient := az.clients.policyClient.NewDefinitionVersionsClient()
	client := az.clients.policyClient.NewDefinitionsClient()

	for _, req := range reqs {
		if az.PolicyDefinitionExists(req.ResourceID.Name, req.Version) {
			continue
		}

		var err error

		switch req.Version {
		case nil:
			err = az.addLatestPolicyDefinition(ctx, client, req)
		default:
			err = az.addVersionedPolicyDefinition(ctx, versionedClient, req)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

// getBuiltInPolicySets retrieves the built-in policy set definitions with the given names
// and adds them to the AlzLib struct.
func (az *AlzLib) getBuiltInPolicySets(ctx context.Context, reqs []BuiltInRequest) error {
	if az.clients.policyClient == nil {
		return errors.New("Alzlib.getBuiltInPolicySets: policy client not set")
	}

	processedRequests := make([]*assets.PolicySetDefinition, 0, len(reqs))

	versionedClient := az.clients.policyClient.NewSetDefinitionVersionsClient()
	client := az.clients.policyClient.NewSetDefinitionsClient()

	for _, req := range reqs {
		if az.PolicySetDefinitionExists(req.ResourceID.Name, req.Version) {
			continue
		}

		var (
			psd *assets.PolicySetDefinition
			err error
		)

		switch req.Version {
		case nil:
			psd, err = az.addLatestPolicySetDefinition(ctx, client, req)
		default:
			psd, err = az.addVersionedPolicySetDefinition(ctx, versionedClient, req)
		}

		if err != nil {
			return err
		}

		processedRequests = append(processedRequests, psd)
	}

	return az.ensureReferencedPolicyDefinitions(ctx, processedRequests)
}

func (az *AlzLib) addLatestPolicyDefinition(ctx context.Context, client *armpolicy.DefinitionsClient, req BuiltInRequest) error {
	resp, err := client.GetBuiltIn(ctx, req.ResourceID.Name, nil)
	if err != nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicies: error getting built-in policy definition %s: %w",
			req.ResourceID.Name,
			err,
		)
	}

	pdv, err := assets.NewPolicyDefinitionValidate(resp.Definition)
	if err != nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicies: converting versionless built-in policy definition to versioned: %s: %w",
			req.ResourceID.Name,
			err,
		)
	}

	if err := az.AddPolicyDefinitions(pdv); err != nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicies: adding built-in policy definition %s: %w",
			req.ResourceID.Name,
			err,
		)
	}

	return nil
}

func (az *AlzLib) addVersionedPolicyDefinition(
	ctx context.Context,
	client *armpolicy.DefinitionVersionsClient,
	req BuiltInRequest,
) error {
	pager := client.NewListBuiltInPager(req.ResourceID.Name, nil)

	pdvs, err := az.collectPolicyDefinitionVersions(ctx, pager, req)
	if err != nil {
		return err
	}

	refVer, err := pdvs.GetVersion(req.Version)
	if err != nil || refVer == nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error getting specific version `%s` of built-in policy definition for `%s`: %w",
			*req.Version,
			req.ResourceID.Name,
			err,
		)
	}

	if err := az.AddPolicyDefinitions(refVer); err != nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicies: adding built-in policy definition %s: %w",
			JoinNameAndVersion(req.ResourceID.Name, req.Version),
			err,
		)
	}

	return nil
}

func (az *AlzLib) collectPolicyDefinitionVersions(
	ctx context.Context,
	pager policyDefinitionVersionsPager,
	req BuiltInRequest,
) (*assets.PolicyDefinitionVersions, error) {
	pdvs := assets.NewPolicyDefinitionVersions()

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf(
				"Alzlib.getBuiltInPolicies: listing built-in policy definition versions for `%s`: %w",
				JoinNameAndVersion(req.ResourceID.Name, req.Version),
				err,
			)
		}

		for _, v := range page.Value {
			pdv, err := assets.NewPolicyDefinitionFromVersionValidate(*v)
			if err != nil {
				return nil, fmt.Errorf(
					"Alzlib.getBuiltInPolicySets: validating built-in policy definition version for `%s`: %w",
					JoinNameAndVersion(req.ResourceID.Name, req.Version),
					err,
				)
			}

			pdvs.Add(pdv, false) // nolint:errcheck
		}
	}

	return pdvs, nil
}

func (az *AlzLib) collectPolicySetDefinitionVersions(
	ctx context.Context,
	pager policySetDefinitionVersionsPager,
	req BuiltInRequest,
) (*assets.PolicySetDefinitionVersions, error) {
	psdvs := assets.NewPolicySetDefinitionVersions()

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf(
				"Alzlib.getBuiltInPolicySets: listing built-in policy set definition versions for `%s`: %w",
				JoinNameAndVersion(req.ResourceID.Name, req.Version),
				err,
			)
		}

		for _, v := range page.Value {
			psd, err := assets.NewPolicySetDefinitionFromVersionValidate(*v)
			if err != nil {
				return nil, fmt.Errorf(
					"Alzlib.getBuiltInPolicySets: validating built-in policy set definition version for `%s`: %w",
					JoinNameAndVersion(req.ResourceID.Name, req.Version),
					err,
				)
			}

			psdvs.Add(psd, false) // nolint:errcheck
		}
	}

	return psdvs, nil
}

func (az *AlzLib) addLatestPolicySetDefinition(
	ctx context.Context,
	client *armpolicy.SetDefinitionsClient,
	req BuiltInRequest,
) (*assets.PolicySetDefinition, error) {
	resp, err := client.GetBuiltIn(ctx, req.ResourceID.Name, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error getting built-in policy set definition %s: %w",
			req.ResourceID.Name,
			err,
		)
	}

	psdv, err := assets.NewPolicySetDefinitionValidate(resp.SetDefinition)
	if err != nil {
		return nil, fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error converting versionless built-in policy set definition to versioned: %s: %w",
			req.ResourceID.Name,
			err,
		)
	}

	if err := az.AddPolicySetDefinitions(psdv); err != nil {
		return nil, fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error adding built-in policy set definition %s: %w",
			req.ResourceID.Name,
			err,
		)
	}

	return psdv, nil
}

func (az *AlzLib) addVersionedPolicySetDefinition(
	ctx context.Context,
	client *armpolicy.SetDefinitionVersionsClient,
	req BuiltInRequest,
) (*assets.PolicySetDefinition, error) {
	pager := client.NewListBuiltInPager(req.ResourceID.Name, nil)

	psdvs, err := az.collectPolicySetDefinitionVersions(ctx, pager, req)
	if err != nil {
		return nil, err
	}

	refVer, err := psdvs.GetVersion(req.Version)
	if err != nil || refVer == nil {
		return nil, fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error getting specific version `%s` of built-in policy set definition for `%s`: %w",
			*req.Version,
			req.ResourceID.Name,
			err,
		)
	}

	if err := az.AddPolicySetDefinitions(refVer); err != nil {
		return nil, fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error adding built-in policy set definition %s: %w",
			req.String(),
			err,
		)
	}

	return refVer, nil
}

func (az *AlzLib) ensureReferencedPolicyDefinitions(
	ctx context.Context,
	processedRequests []*assets.PolicySetDefinition,
) error {
	if len(processedRequests) == 0 {
		return nil
	}

	definitionsVersionedClient := az.clients.policyClient.NewDefinitionVersionsClient()
	definitionsClient := az.clients.policyClient.NewDefinitionsClient()

	for _, def := range processedRequests {
		for _, ref := range def.Properties.PolicyDefinitions {
			err := az.ensureReferencedPolicyDefinition(
				ctx,
				definitionsClient,
				definitionsVersionedClient,
				def,
				ref,
			)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (az *AlzLib) ensureReferencedPolicyDefinition(
	ctx context.Context,
	definitionsClient *armpolicy.DefinitionsClient,
	definitionsVersionedClient *armpolicy.DefinitionVersionsClient,
	setDefinition *assets.PolicySetDefinition,
	ref *armpolicy.DefinitionReference,
) error {
	if ref == nil {
		return nil
	}

	if ref.PolicyDefinitionID == nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error getting policy definition references for policy set definition `%s`: "+
				"policy definition ID is nil",
			JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
		)
	}

	resID, err := arm.ParseResourceID(*ref.PolicyDefinitionID)
	if err != nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: error parsing resource id `%s` referenced in policy set `%s`",
			*ref.PolicyDefinitionID,
			JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
		)
	}

	if ref.DefinitionVersion != nil {
		return az.fetchReferencedPolicyDefinitionVersions(ctx, definitionsVersionedClient, resID.Name, setDefinition, ref)
	}

	return az.fetchLatestReferencedPolicyDefinition(ctx, definitionsClient, resID.Name, setDefinition, ref.DefinitionVersion)
}

func (az *AlzLib) fetchReferencedPolicyDefinitionVersions(
	ctx context.Context,
	client *armpolicy.DefinitionVersionsClient,
	definitionName string,
	setDefinition *assets.PolicySetDefinition,
	ref *armpolicy.DefinitionReference,
) error {
	pager := client.NewListBuiltInPager(definitionName, nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf(
				"Alzlib.getBuiltInPolicySets: error listing built-in policy definition versions for `%s`, referenced in policy set `%s`: %w",
				definitionName,
				JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
				err,
			)
		}

		for _, v := range page.Value {
			pdv, err := assets.NewPolicyDefinitionFromVersionValidate(*v)
			if err != nil {
				return fmt.Errorf(
					"Alzlib.getBuiltInPolicySets: error validating built-in policy definition version for `%s`, referenced in policy set `%s`: %w",
					definitionName,
					JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
					err,
				)
			}

			az.AddPolicyDefinitions(pdv) // nolint:errcheck
		}
	}

	if !az.PolicyDefinitionExists(definitionName, ref.DefinitionVersion) {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: finding specific version constraint `%s` of built-in policy definition "+
				"for `%s`, referenced in policy set `%s`. Versions available: %v",
			*ref.DefinitionVersion,
			definitionName,
			JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
			az.policyDefinitions[definitionName].Versions(),
		)
	}

	return nil
}

func (az *AlzLib) fetchLatestReferencedPolicyDefinition(
	ctx context.Context,
	client *armpolicy.DefinitionsClient,
	definitionName string,
	setDefinition *assets.PolicySetDefinition,
	desiredVersion *string,
) error {
	pd, err := client.GetBuiltIn(ctx, definitionName, nil)
	if err != nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: getting versionless built-in policy definition %s, referenced in policy set `%s`: %w",
			definitionName,
			JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
			err,
		)
	}

	pdvLatest, err := assets.NewPolicyDefinitionValidate(pd.Definition)
	if err != nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: validating versionless built-in policy definition %s, referenced in policy set `%s`: %w",
			definitionName,
			JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
			err,
		)
	}

	if err := az.AddPolicyDefinitions(pdvLatest); err != nil {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: adding versionless built-in policy definition %s, referenced in policy set `%s`: %w",
			definitionName,
			JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
			err,
		)
	}

	if !az.PolicyDefinitionExists(definitionName, desiredVersion) {
		return fmt.Errorf(
			"Alzlib.getBuiltInPolicySets: finding versionless built-in policy definition "+
				"for `%s`, referenced in policy set `%s`",
			definitionName,
			JoinNameAndVersion(*setDefinition.Name, setDefinition.Properties.Version),
		)
	}

	return nil
}

// addPolicyAndRoleAssets adds the results of a processed library to the AlzLib.
func (az *AlzLib) addPolicyAndRoleAssets(res *processor.Result) error {
	var merr multierror.Error

	for k, v := range res.PolicyDefinitions {
		if pdv, exists := az.policyDefinitions[k]; exists {
			merr.Errors = append(merr.Errors, v.Upsert(pdv, az.Options.AllowOverwrite))
			continue
		}

		az.policyDefinitions[k] = v
	}

	if err := merr.ErrorOrNil(); err != nil {
		return fmt.Errorf("Alzlib.addProcessedResult: error adding policy definition versions: %w", err)
	}

	for k, v := range res.PolicySetDefinitions {
		if psdv, exists := az.policySetDefinitions[k]; exists {
			merr.Errors = append(merr.Errors, v.Upsert(psdv, az.Options.AllowOverwrite))
			continue
		}

		az.policySetDefinitions[k] = v
	}

	if err := merr.ErrorOrNil(); err != nil {
		return fmt.Errorf("Alzlib.addProcessedResult: error adding policy set definition versions: %w", err)
	}

	for k, v := range res.PolicyAssignments {
		if _, exists := az.policyAssignments[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf(
				"Alzlib.addProcessedResult: policy assignment %s already exists in the library",
				k,
			)
		}

		az.policyAssignments[k] = v
	}

	for k, v := range res.RoleDefinitions {
		if _, exists := az.roleDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf(
				"Alzlib.addProcessedResult: role definition %s already exists in the library",
				k,
			)
		}

		az.roleDefinitions[k] = v
	}

	return nil
}

func (az *AlzLib) addDefaultPolicyAssignmentValues(res *processor.Result) error {
	for defName, def := range res.LibDefaultPolicyValues {
		if _, exists := az.defaultPolicyAssignmentValues[defName]; exists {
			if !az.Options.AllowOverwrite {
				return fmt.Errorf(
					"Alzlib.addDefaultPolicyValues: default name %s already exists in the defaults",
					defName,
				)
			}

			delete(az.defaultPolicyAssignmentValues, defName)
		}

		for _, assignment := range def.PolicyAssignments {
			for _, param := range assignment.ParameterNames {
				if az.defaultPolicyAssignmentValues.AssignmentParameterComboExists(
					assignment.PolicyAssignmentName,
					param,
				) {
					return fmt.Errorf(
						"Alzlib.addDefaultPolicyValues: error processing default policy values for default name: `%s`, "+
							"assignment `%s` and parameter `%s` already exists in defaults",
						defName,
						assignment.PolicyAssignmentName,
						param,
					)
				}
			}

			az.defaultPolicyAssignmentValues.Add(
				defName,
				assignment.PolicyAssignmentName,
				def.Description,
				assignment.ParameterNames...)
		}
	}

	return nil
}

// generateArchetypes generates the archetypes from the result of the processor.
// The archetypes are stored in the AlzLib instance.
func (az *AlzLib) generateArchetypes(res *processor.Result) error {
	// add empty archetype if it doesn't exist.
	if _, exists := az.archetypes["empty"]; !exists {
		if _, exists := res.LibArchetypes["empty"]; !exists {
			res.LibArchetypes["empty"] = &processor.LibArchetype{
				Name:                 "empty",
				PolicyAssignments:    mapset.NewThreadUnsafeSet[string](),
				PolicyDefinitions:    mapset.NewThreadUnsafeSet[string](),
				PolicySetDefinitions: mapset.NewThreadUnsafeSet[string](),
				RoleDefinitions:      mapset.NewThreadUnsafeSet[string](),
			}
		}
	}

	// generate alzlib archetypes.
	for k, v := range res.LibArchetypes {
		if _, exists := az.archetypes[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf(
				"Alzlib.generateArchetypes: archetype %s already exists in the library",
				v.Name,
			)
		}

		arch := NewArchetype(v.Name)

		for pd := range v.PolicyDefinitions.Iter() {
			if _, ok := az.policyDefinitions[pd]; !ok {
				return fmt.Errorf(
					"Alzlib.generateArchetypes: error processing archetype %s, policy definition %s does not exist in the library",
					k,
					pd,
				)
			}

			arch.PolicyDefinitions.Add(pd)
		}

		for psd := range v.PolicySetDefinitions.Iter() {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf(
					"Alzlib.generateArchetypes: error processing archetype %s, policy set definition %s does not exist in the library",
					k,
					psd,
				)
			}

			arch.PolicySetDefinitions.Add(psd)
		}

		for pa := range v.PolicyAssignments.Iter() {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf(
					"Alzlib.generateArchetypes: error processing archetype %s, policy assignment %s does not exist in the library",
					k,
					pa,
				)
			}

			arch.PolicyAssignments.Add(pa)
		}

		for rd := range v.RoleDefinitions.Iter() {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf(
					"Alzlib.generateArchetypes: error processing archetype %s, role definition %s does not exist in the library",
					k,
					rd,
				)
			}

			arch.RoleDefinitions.Add(rd)
		}

		az.archetypes[v.Name] = arch
	}

	return nil
}

// generateOverrideArchetypes generates the override archetypes from the result of the processor.
// THis must be run after generateArchetypes.
func (az *AlzLib) generateOverrideArchetypes(res *processor.Result) error {
	for name, ovr := range res.LibArchetypeOverrides {
		if _, exists := az.archetypes[name]; exists {
			return fmt.Errorf(
				"Alzlib.generateOverrideArchetypes: error processing override archetype `%s` - it already exists in the library",
				name,
			)
		}

		base, exists := az.archetypes[ovr.BaseArchetype]
		if !exists {
			return fmt.Errorf(
				"Alzlib.generateOverrideArchetypes: error processing override archetype `%s` - "+
					"base archetype `%s` does not exist in the library",
				name,
				ovr.BaseArchetype,
			)
		}

		for pa := range ovr.PolicyAssignmentsToAdd.Iter() {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf(
					"Alzlib.generateOverrideArchetypes: error processing override archetype `%s`, "+
						"policy assignment `%s` does not exist in the library",
					name,
					pa,
				)
			}
		}

		for pa := range ovr.PolicyAssignmentsToRemove.Iter() {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf(
					"Alzlib.generateOverrideArchetypes: error processing override archetype `%s`, "+
						"policy assignment `%s` does not exist in the library",
					name,
					pa,
				)
			}
		}

		for pd := range ovr.PolicyDefinitionsToAdd.Iter() {
			if _, ok := az.policyDefinitions[pd]; !ok {
				return fmt.Errorf(
					"Alzlib.generateOverrideArchetypes: error processing override archetype `%s`, "+
						"policy definition `%s` does not exist in the library",
					name,
					pd,
				)
			}
		}

		for pd := range ovr.PolicyDefinitionsToRemove.Iter() {
			if _, ok := az.policyDefinitions[pd]; !ok {
				return fmt.Errorf(
					"Alzlib.generateOverrideArchetypes: error processing override archetype `%s`, "+
						"policy definition `%s` does not exist in the library",
					name,
					pd,
				)
			}
		}

		for psd := range ovr.PolicySetDefinitionsToAdd.Iter() {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf(
					"Alzlib.generateOverrideArchetypes: error processing override archetype `%s`, "+
						"policy set definition `%s` does not exist in the library",
					name,
					psd,
				)
			}
		}

		for psd := range ovr.PolicySetDefinitionsToRemove.Iter() {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf(
					"Alzlib.generateOverrideArchetypes: error processing override archetype `%s`, "+
						"policy set definition `%s` does not exist in the library",
					name,
					psd,
				)
			}
		}

		for rd := range ovr.RoleDefinitionsToAdd.Iter() {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf(
					"Alzlib.generateOverrideArchetypes: error processing override archetype `%s`, "+
						"role definition `%s` does not exist in the library",
					name,
					rd,
				)
			}
		}

		for rd := range ovr.RoleDefinitionsToRemove.Iter() {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf(
					"Alzlib.generateOverrideArchetypes: error processing override archetype `%s`, "+
						"role definition `%s` does not exist in the library",
					name,
					rd,
				)
			}
		}

		newArch := &Archetype{
			PolicyDefinitions: base.PolicyDefinitions.Clone().
				Union(ovr.PolicyDefinitionsToAdd).
				Difference(ovr.PolicyDefinitionsToRemove),
			PolicySetDefinitions: base.PolicySetDefinitions.Clone().
				Union(ovr.PolicySetDefinitionsToAdd).
				Difference(ovr.PolicySetDefinitionsToRemove),
			PolicyAssignments: base.PolicyAssignments.Clone().
				Union(ovr.PolicyAssignmentsToAdd).
				Difference(ovr.PolicyAssignmentsToRemove),
			RoleDefinitions: base.RoleDefinitions.Clone().
				Union(ovr.RoleDefinitionsToAdd).
				Difference(ovr.RoleDefinitionsToRemove),
			name: name,
		}
		az.archetypes[name] = newArch
	}

	return nil
}

func (az *AlzLib) generateArchitectures(res *processor.Result) error {
	for name, libArch := range res.LibArchitectures {
		if _, exists := az.architectures[name]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf(
				"Alzlib.generateArchitectures: error processing architecture %s - it already exists in the library",
				name,
			)
		}

		validParents := mapset.NewThreadUnsafeSet[string]()
		for _, mg := range libArch.ManagementGroups {
			validParents.Add(mg.ID)
		}

		for _, mg := range libArch.ManagementGroups {
			if mg.ParentID != nil && !validParents.Contains(*mg.ParentID) {
				return fmt.Errorf(
					"Alzlib.generateArchitectures: error processing architecture %s - management group %s has invalid parent %s",
					name,
					mg.ID,
					*mg.ParentID,
				)
			}
		}

		arch := NewArchitecture(name, az)
		if err := architectureRecursion(nil, libArch, arch, az, 0); err != nil {
			return fmt.Errorf(
				"Alzlib.generateArchitectures: error processing architecture %s: %w",
				name,
				err,
			)
		}

		az.architectures[name] = arch
	}

	return nil
}

// architectureRecursion is a recursive function to build the architecture from the definitions read
// by the processor.
func architectureRecursion(
	parents mapset.Set[string],
	libArch *processor.LibArchitecture,
	arch *Architecture,
	az *AlzLib,
	depth int,
) error {
	if depth > MaxRecursionDepth {
		return errors.New("architectureRecursion: recursion depth exceeded")
	}

	newParents := mapset.NewThreadUnsafeSet[string]()

	if len(libArch.ManagementGroups) == 0 {
		return errors.New("architectureRecursion: no management groups found")
	}

	for _, mg := range libArch.ManagementGroups {
		switch {
		case depth == 0 && mg.ParentID == nil:
			if err := arch.addMgFromProcessor(mg, az); err != nil {
				return fmt.Errorf("architectureRecursion: error adding management group %s: %w", mg.ID, err)
			}
		case depth > 0 && mg.ParentID != nil:
			if parents == nil {
				return errors.New("architectureRecursion: depth > 1 and parents set to nil")
			}

			if !parents.Contains(*mg.ParentID) {
				continue
			}

			if !arch.mgs[*mg.ParentID].exists && mg.Exists {
				return fmt.Errorf(
					"architectureRecursion: error adding management group %s, which is configured as existing "+
						"but the parent management group %s does not exist and would be created",
					mg.ID,
					*mg.ParentID,
				)
			}

			if err := arch.addMgFromProcessor(mg, az); err != nil {
				return fmt.Errorf("architectureRecursion: error adding management group %s: %w", mg.ID, err)
			}
		default:
			continue
		}

		newParents.Add(mg.ID)
	}

	if newParents.Cardinality() > 0 {
		return architectureRecursion(newParents, libArch, arch, az, depth+1)
	}

	return nil
}
