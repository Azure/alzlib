// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/processor"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/brunoga/deep"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/hashicorp/go-getter/v2"
	"golang.org/x/sync/errgroup"
)

const (
	defaultParallelism = 10 // default number of parallel requests to make to Azure APIs
)

// AlzLib is the structure that gets built from the the library files
// do not create this directly, use NewAlzLib instead.
// Note: this is not thread safe, and should not be used concurrently without an external mutex.
type AlzLib struct {
	Options *AlzLibOptions

	archetypes           map[string]*archetype
	architectures        map[string]*Architecture
	policyAssignments    map[string]*assets.PolicyAssignment
	policyDefinitions    map[string]*assets.PolicyDefinition
	policySetDefinitions map[string]*assets.PolicySetDefinition
	roleDefinitions      map[string]*assets.RoleDefinition
	clients              *azureClients
	mu                   sync.RWMutex // mu is a mutex to concurrency protect the AlzLib maps
}

type azureClients struct {
	policyClient *armpolicy.ClientFactory
}

// AlzLibOptions are options for the AlzLib.
// This is created by NewAlzLib.
type AlzLibOptions struct {
	AllowOverwrite bool // AllowOverwrite allows overwriting of existing policy assignments when processing additional libraries with AlzLib.Init()
	Parallelism    int  // Parallelism is the number of parallel requests to make to Azure APIs
}

// NewAlzLib returns a new instance of the alzlib library, optionally using the supplied directory
// for additional policy (set) definitions.
func NewAlzLib(opts *AlzLibOptions) *AlzLib {
	if opts == nil {
		opts = defaultAlzLibOptions()
	}
	az := &AlzLib{
		Options:              opts,
		archetypes:           make(map[string]*archetype),
		architectures:        make(map[string]*Architecture),
		policyAssignments:    make(map[string]*assets.PolicyAssignment),
		policyDefinitions:    make(map[string]*assets.PolicyDefinition),
		policySetDefinitions: make(map[string]*assets.PolicySetDefinition),
		roleDefinitions:      make(map[string]*assets.RoleDefinition),
		clients:              new(azureClients),
		mu:                   sync.RWMutex{},
	}
	return az
}

func defaultAlzLibOptions() *AlzLibOptions {
	return &AlzLibOptions{
		Parallelism:    defaultParallelism,
		AllowOverwrite: false,
	}
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
			return fmt.Errorf("Alzlib.AddPolicyAssignments: policy assignment with name %s already exists and allow overwrite not set", *pa.Name)
		}
		cpy, err := deep.Copy(pa)
		if err != nil {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: error making deep copy of policy assignment %s: %w", *pa.Name, err)
		}
		az.policyAssignments[*pa.Name] = cpy
	}
	return nil
}

// AddPolicyDefinitions adds policy definitions to the AlzLib struct.
func (az *AlzLib) AddPolicyDefinitions(pds ...*assets.PolicyDefinition) error {
	az.mu.Lock()
	defer az.mu.Unlock()
	for _, pd := range pds {
		if pd == nil || pd.Name == nil || *pd.Name == "" {
			continue
		}

		if _, exists := az.policyDefinitions[*pd.Name]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: policy definition with name %s already exists and allow overwrite not set", *pd.Name)
		}
		cpy, err := deep.Copy(pd)
		if err != nil {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: error making deep copy of policy definition %s: %w", *pd.Name, err)
		}
		az.policyDefinitions[*pd.Name] = cpy
	}
	return nil
}

// AddPolicySetDefinitions adds policy set definitions to the AlzLib struct.
func (az *AlzLib) AddPolicySetDefinitions(psds ...*assets.PolicySetDefinition) error {
	az.mu.Lock()
	defer az.mu.Unlock()
	for _, psd := range psds {
		if psd == nil || psd.Name == nil || *psd.Name == "" {
			continue
		}
		if _, exists := az.policyDefinitions[*psd.Name]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: policy set definition with name %s already exists and allow overwrite not set", *psd.Name)
		}
		cpy, err := deep.Copy(psd)
		if err != nil {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: error making deep copy of policy set definition %s: %w", *psd.Name, err)
		}
		az.policySetDefinitions[*psd.Name] = cpy
	}
	return nil
}

// AddRoleDefinitions adds role definitions to the AlzLib struct.
func (az *AlzLib) AddRoleDefinitions(rds ...*assets.RoleDefinition) error {
	az.mu.Lock()
	defer az.mu.Unlock()
	for _, rd := range rds {
		if rd == nil || rd.Name == nil || *rd.Name == "" {
			continue
		}
		if _, exists := az.policyDefinitions[*rd.Name]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: role definition with name %s already exists and allow overwrite not set", *rd.Name)
		}
		cpy, err := deep.Copy(rd)
		if err != nil {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: error making deep copy of role definition %s: %w", *rd.Name, err)
		}
		az.roleDefinitions[*rd.Name] = cpy
	}
	return nil
}

// Archetypes returns a list of the archetypes in the AlzLib struct.
func (az *AlzLib) Archetypes() []string {
	az.mu.RLock()
	defer az.mu.RUnlock()
	result := make([]string, 0, len(az.archetypes))
	for k := range az.archetypes {
		result = append(result, k)
	}
	return result
}

// Archetype returns a copy of the requested archetype by name.
// The returned struct can be used as a parameter to the Deployment.AddManagementGroup method.
func (az *AlzLib) Archetype(name string) (*Archetype, error) {
	az.mu.RLock()
	defer az.mu.RUnlock()
	if arch, ok := az.archetypes[name]; ok {
		return arch.copy(), nil
	}
	return nil, fmt.Errorf("Alzlib.CopyArchetype: archetype %s not found", name)
}

// Architecture returns the requested architecture.
func (az *AlzLib) Architecture(name string) (*Architecture, error) {
	az.mu.RLock()
	defer az.mu.RUnlock()
	if arch, ok := az.architectures[name]; ok {
		return arch, nil
	}
	return nil, fmt.Errorf("Alzlib.Architecture: architecture %s not found", name)
}

// PolicyDefinitionExists returns true if the policy definition exists in the AlzLib struct.
func (az *AlzLib) PolicyDefinitionExists(name string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()
	_, exists := az.policyDefinitions[name]
	return exists
}

// PolicySetDefinitionExists returns true if the policy set definition exists in the AlzLib struct.
func (az *AlzLib) PolicySetDefinitionExists(name string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()
	_, exists := az.policySetDefinitions[name]
	return exists
}

// PolicyAssignmentExists returns true if the policy assignment exists in the AlzLib struct.
func (az *AlzLib) PolicyAssignmentExists(name string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()
	_, exists := az.policyAssignments[name]
	return exists
}

// RoleDefinitionExists returns true if the role definition exists in the AlzLib struct.
func (az *AlzLib) RoleDefinitionExists(name string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()
	_, exists := az.roleDefinitions[name]
	return exists
}

// PolicyDefinition returns a deep copy of the requested policy definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) PolicyDefinition(name string) (*assets.PolicyDefinition, error) {
	az.mu.RLock()
	defer az.mu.RUnlock()
	if pd, exists := az.policyDefinitions[name]; exists {
		return deep.Copy(pd)
	}
	return nil, fmt.Errorf("Alzlib.GetPolicyDefinition: policy definition %s not found", name)
}

// GetPolicySetDefinition returns a deep copy of the requested policy set definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) PolicyAssignment(name string) (*assets.PolicyAssignment, error) {
	az.mu.RLock()
	defer az.mu.RUnlock()
	if pa, exists := az.policyAssignments[name]; exists {
		return deep.Copy(pa)
	}
	return nil, fmt.Errorf("Alzlib.GetPolicyAssignment: policy assignment %s not found", name)
}

// PolicySetDefinition returns a deep copy of the requested policy set definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) PolicySetDefinition(name string) (*assets.PolicySetDefinition, error) {
	az.mu.RLock()
	defer az.mu.RUnlock()
	if psd, exists := az.policySetDefinitions[name]; exists {
		return deep.Copy(psd)
	}
	return nil, fmt.Errorf("Alzlib.GetPolicySetDefinition: policy set definition %s not found", name)
}

// RoleDefinition returns a deep copy of the requested role definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) RoleDefinition(name string) (*assets.RoleDefinition, error) {
	az.mu.RLock()
	defer az.mu.RUnlock()
	if rd, exists := az.roleDefinitions[name]; exists {
		return deep.Copy(rd)
	}
	return nil, fmt.Errorf("Alzlib.GetRoleDefinition: role definition %s not found", name)
}

// AddPolicyClient adds an authenticated *armpolicy.ClientFactory to the AlzLib struct.
// This is needed to get policy objects from Azure.
func (az *AlzLib) AddPolicyClient(client *armpolicy.ClientFactory) {
	az.mu.Lock()
	defer az.mu.Unlock()
	az.clients.policyClient = client
}

// Init processes ALZ libraries, supplied as fs.FS interfaces.
// Use FetchAzureLandingZonesLibraryMember to get the library from GitHub.
// It populates the struct with the results of the processing.
func (az *AlzLib) Init(ctx context.Context, libs ...fs.FS) error {
	az.mu.Lock()
	defer az.mu.Unlock()
	if az.Options == nil || az.Options.Parallelism == 0 {
		return errors.New("Alzlib.Init: alzlib Options not set or parallelism is `0`")
	}

	// Process the libraries
	for _, lib := range libs {
		if lib == nil {
			return errors.New("Alzlib.Init: library is nil")
		}
		res := new(processor.Result)
		pc := processor.NewProcessorClient(lib)
		if err := pc.Process(res); err != nil {
			return fmt.Errorf("Alzlib.Init: error processing library %v: %w", lib, err)
		}

		// Put results into the AlzLib.
		if err := az.addProcessedResult(res); err != nil {
			return fmt.Errorf("Alzlib.Init: error adding processed result to AlzLib: %w", err)
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

// GetDefinitionsFromAzure takes a slice of strings containing Azure resource IDs of policy definitions and policy set definitions.
// It then fetches them from Azure if needed and adds them to the AlzLib struct.
// For set definitions we need to get all of them, even if they exist in AlzLib already because they can contain built-in definitions.
func (az *AlzLib) GetDefinitionsFromAzure(ctx context.Context, pds []string) error {
	policyDefsToGet := mapset.NewThreadUnsafeSet[string]()
	policySetDefsToGet := mapset.NewThreadUnsafeSet[string]()
	for _, pd := range pds {
		resId, err := arm.ParseResourceID(pd)
		if err != nil {
			return fmt.Errorf("Alzlib.GetDefinitionsFromAzure: error parsing resource ID %s: %w", pd, err)
		}
		switch strings.ToLower(resId.ResourceType.Type) {
		case "policydefinitions":
			if !az.PolicyDefinitionExists(resId.Name) {
				policyDefsToGet.Add(resId.Name)
			}
		case "policysetdefinitions":
			// If the set is not present, OR if the set contains referenced definitions that are not present
			// add it to the list of set defs to get.
			exists := az.PolicySetDefinitionExists(resId.Name)
			if exists {
				psd, err := az.PolicySetDefinition(resId.Name)
				if err != nil {
					return fmt.Errorf("Alzlib.GetDefinitionsFromAzure: error getting policy set definition %s: %w", pd, err)
				}
				pdrefs, err := psd.PolicyDefinitionReferences()
				if err != nil {
					return fmt.Errorf("Alzlib.GetDefinitionsFromAzure: error getting policy definition references for policy set definition %s: %w", pd, err)
				}
				for _, ref := range pdrefs {
					subResId, err := arm.ParseResourceID(*ref.PolicyDefinitionID)
					if err != nil {
						return fmt.Errorf("Alzlib.GetDefinitionsFromAzure: policy set definition %s error parsing referenced definition resource id: %w", *psd.Name, err)
					}
					if _, exists := az.policyDefinitions[subResId.Name]; !exists {
						policyDefsToGet.Add(subResId.Name)
					}
				}
			} else {
				policySetDefsToGet.Add(resId.Name)
			}

		default:
			return fmt.Errorf("Alzlib.GetDefinitionsFromAzure: unexpected policy definition type when processing assignments: %s", pd)
		}
	}

	// Add the referenced built-in definitions and set definitions to the AlzLib struct
	// so that we can use the data to determine the correct role assignments at scope.
	if policyDefsToGet.Cardinality() != 0 {
		if err := az.getBuiltInPolicies(ctx, policyDefsToGet.ToSlice()); err != nil {
			return fmt.Errorf("Alzlib.GetDefinitionsFromAzure: error getting built-in policy definitions: %w", err)
		}
	}
	if policySetDefsToGet.Cardinality() != 0 {
		if err := az.getBuiltInPolicySets(ctx, policySetDefsToGet.ToSlice()); err != nil {
			return fmt.Errorf("Alzlib.GetDefinitionsFromAzure: error getting built-in policy set definitions: %w", err)
		}
	}
	return nil
}

// getBuiltInPolicies retrieves the built-in policy definitions with the given names
// and adds them to the AlzLib struct.
func (az *AlzLib) getBuiltInPolicies(ctx context.Context, names []string) error {
	if az.clients.policyClient == nil {
		return errors.New("Alzlib.getBuiltInPolicies: policy client not set")
	}
	grp, ctx := errgroup.WithContext(ctx)
	grp.SetLimit(az.Options.Parallelism)
	pdclient := az.clients.policyClient.NewDefinitionsClient()
	for _, name := range names {
		name := name
		grp.Go(func() error {
			az.mu.Lock()
			defer az.mu.Unlock()
			if _, exists := az.policyDefinitions[name]; exists {
				return nil
			}
			resp, err := pdclient.GetBuiltIn(ctx, name, nil)
			if err != nil {
				return fmt.Errorf("error getting built-in policy definition %s: %w", name, err)
			}
			az.policyDefinitions[name] = assets.NewPolicyDefinition(resp.Definition)
			return nil
		})
	}
	if err := grp.Wait(); err != nil {
		return fmt.Errorf("Alzlib.getBuiltInPolicies: error from errorgroup.Group: %w", err)
	}
	return nil
}

// getBuiltInPolicySets retrieves the built-in policy set definitions with the given names
// and adds them to the AlzLib struct.
func (az *AlzLib) getBuiltInPolicySets(ctx context.Context, names []string) error {
	if az.clients.policyClient == nil {
		return errors.New("Alzlib.getBuiltInPolicySets: policy client not set")
	}
	grp, ctxErrGroup := errgroup.WithContext(ctx)
	grp.SetLimit(az.Options.Parallelism)

	// We need to keep track of the names we've processed
	// so that we can get the policy definitions referenced within them.
	processedNames := make([]string, 0, len(names))
	var mu sync.Mutex

	psclient := az.clients.policyClient.NewSetDefinitionsClient()
	for _, name := range names {
		name := name
		grp.Go(func() error {
			az.mu.Lock()
			defer az.mu.Unlock()
			if _, exists := az.policySetDefinitions[name]; exists {
				return nil
			}
			resp, err := psclient.GetBuiltIn(ctxErrGroup, name, nil)
			if err != nil {
				return fmt.Errorf("error getting built-in policy set definition %s: %w", name, err)
			}
			// Add set definition to the AlzLib.
			az.policySetDefinitions[name] = assets.NewPolicySetDefinition(resp.SetDefinition)
			// Add name to processedNames.
			mu.Lock()
			defer mu.Unlock()
			processedNames = append(processedNames, name)
			return nil
		})
	}
	if err := grp.Wait(); err != nil {
		return fmt.Errorf("Alzlib.getBuiltInPolicySets: error from errorgroup.Group: %w", err)
	}

	// Get the policy definitions for newly added policy set definitions.
	defnames := make([]string, 0)
	for _, name := range names {
		name := name
		refs, err := az.policySetDefinitions[name].PolicyDefinitionReferences()
		if err != nil {
			return fmt.Errorf("Alzlib.getBuiltInPolicySets: error getting policy definition references for policy set definition %s: %w", name, err)
		}
		for _, ref := range refs {
			resId, err := arm.ParseResourceID(*ref.PolicyDefinitionID)
			if err != nil {
				if ref.PolicyDefinitionID == nil {
					return fmt.Errorf("Alzlib.getBuiltInPolicySets: error getting policy definition references for policy set definition %s: policy definition ID is nil", name)
				}
				return fmt.Errorf("Alzlib.getBuiltInPolicySets: error parsing resource id %s referenced in policy set %s", *ref.PolicyDefinitionID, name)
			}
			defnames = append(defnames, resId.Name)
		}
	}
	if err := az.getBuiltInPolicies(ctx, defnames); err != nil {
		return fmt.Errorf("Alzlib.getBuiltInPolicySets: error getting new built-in policy definitions referenced by policy sets: %w", err)
	}

	return nil
}

// addProcessedResult adds the results of a processed library to the AlzLib.
func (az *AlzLib) addProcessedResult(res *processor.Result) error {
	for k, v := range res.PolicyDefinitions {
		if _, exists := az.policyDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("Alzlib.addProcessedResult: policy definition %s already exists in the library", k)
		}
		az.policyDefinitions[k] = assets.NewPolicyDefinition(*v)
	}
	for k, v := range res.PolicySetDefinitions {
		if _, exists := az.policySetDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("Alzlib.addProcessedResult: policy definition %s already exists in the library", k)
		}
		az.policySetDefinitions[k] = assets.NewPolicySetDefinition(*v)
	}
	for k, v := range res.PolicyAssignments {
		if _, exists := az.policyAssignments[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("Alzlib.addProcessedResult: policy assignment %s already exists in the library", k)
		}
		az.policyAssignments[k] = assets.NewPolicyAssignment(*v)
	}
	for k, v := range res.RoleDefinitions {
		if _, exists := az.roleDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("Alzlib.addProcessedResult: role definition %s already exists in the library", k)
		}
		az.roleDefinitions[k] = assets.NewRoleDefinition(*v)
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
			return fmt.Errorf("Alzlib.generateArchetypes: archetype %s already exists in the library", v.Name)
		}
		arch := newArchitype(v.Name)
		for pd := range v.PolicyDefinitions.Iter() {
			if _, ok := az.policyDefinitions[pd]; !ok {
				return fmt.Errorf("Alzlib.generateArchetypes: error processing archetype %s, policy definition %s does not exist in the library", k, pd)
			}
			arch.policyDefinitions.Add(pd)
		}
		for psd := range v.PolicySetDefinitions.Iter() {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf("Alzlib.generateArchetypes: error processing archetype %s, policy set definition %s does not exist in the library", k, psd)
			}
			arch.policySetDefinitions.Add(psd)
		}
		for pa := range v.PolicyAssignments.Iter() {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf("Alzlib.generateArchetypes: error processing archetype %s, policy assignment %s does not exist in the library", k, pa)
			}
			arch.policyAssignments.Add(pa)
		}
		for rd := range v.RoleDefinitions.Iter() {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf("Alzlib.generateArchetypes: error processing archetype %s, role definition %s does not exist in the library", k, rd)
			}
			arch.roleDefinitions.Add(rd)
		}
		az.archetypes[v.Name] = arch
	}
	return nil
}

func (az *AlzLib) generateOverrideArchetypes(res *processor.Result) error {
	for name, ovr := range res.LibArchetypeOverrides {
		if _, exists := az.archetypes[name]; exists {
			return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s - it already exists in the library", name)
		}
		base, exists := az.archetypes[ovr.BaseArchetype]
		if !exists {
			return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s - base archetype %s does not exist in the library", name, ovr.BaseArchetype)
		}
		for pa := range ovr.PolicyAssignmentsToAdd.Iter() {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s, policy assignment %s does not exist in the library", name, pa)
			}
		}
		for pa := range ovr.PolicyAssignmentsToRemove.Iter() {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s, policy assignment %s does not exist in the library", name, pa)
			}
		}
		for pd := range ovr.PolicyDefinitionsToAdd.Iter() {
			if _, ok := az.policyDefinitions[pd]; !ok {
				return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s, policy definition %s does not exist in the library", name, pd)
			}
		}
		for pd := range ovr.PolicyDefinitionsToRemove.Iter() {
			if _, ok := az.policyDefinitions[pd]; !ok {
				return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s, policy definition %s does not exist in the library", name, pd)
			}
		}
		for psd := range ovr.PolicySetDefinitionsToAdd.Iter() {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s, policy set definition %s does not exist in the library", name, psd)
			}
		}
		for psd := range ovr.PolicySetDefinitionsToRemove.Iter() {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s, policy set definition %s does not exist in the library", name, psd)
			}
		}
		for rd := range ovr.RoleDefinitionsToAdd.Iter() {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s, role definition %s does not exist in the library", name, rd)
			}
		}
		for rd := range ovr.RoleDefinitionsToRemove.Iter() {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf("Alzlib.generateOverrideArchetypes: error processing override archetype %s, role definition %s does not exist in the library", name, rd)
			}
		}

		newArch := &archetype{
			policyDefinitions:    base.policyDefinitions.Clone().Union(ovr.PolicyDefinitionsToAdd).Difference(ovr.PolicyDefinitionsToRemove),
			policySetDefinitions: base.policySetDefinitions.Clone().Union(ovr.PolicySetDefinitionsToAdd).Difference(ovr.PolicySetDefinitionsToRemove),
			policyAssignments:    base.policyAssignments.Clone().Union(ovr.PolicyAssignmentsToAdd).Difference(ovr.PolicyAssignmentsToRemove),
			roleDefinitions:      base.roleDefinitions.Clone().Union(ovr.RoleDefinitionsToAdd).Difference(ovr.RoleDefinitionsToRemove),
			name:                 name,
		}
		az.archetypes[name] = newArch
	}
	return nil
}

func (az *AlzLib) generateArchitectures(res *processor.Result) error {
	for name, libArch := range res.LibArchitectures {
		if _, exists := az.architectures[name]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("Alzlib.generateArchitectures: error processing architecture %s - it already exists in the library", name)
		}
		arch := NewArchitecture(name, az)
		if err := architectureRecursion(nil, libArch, arch, az, 0); err != nil {
			return fmt.Errorf("Alzlib.generateArchitectures: error processing architecture %s: %w", name, err)
		}
		az.architectures[name] = arch
	}
	return nil
}

func architectureRecursion(parents mapset.Set[string], libArch *processor.LibArchitecture, arch *Architecture, az *AlzLib, depth int) error {
	if depth > 5 {
		return errors.New("architectureRecursion: recursion depth exceeded")
	}
	newParents := mapset.NewThreadUnsafeSet[string]()
	if len(libArch.ManagementGroups) == 0 {
		return errors.New("architectureRecursion: no management groups found")
	}
	for _, mg := range libArch.ManagementGroups {
		parentFound := false
		switch {
		case depth == 0 && mg.ParentId == nil:
			if err := arch.addMgFromProcessor(mg, az); err != nil {
				return fmt.Errorf("architectureRecursion: error adding management group %s: %w", mg.Id, err)
			}
			parentFound = true
		case depth > 0 && mg.ParentId != nil:
			if parents == nil {
				return errors.New("architectureRecursion: depth > 1 and parents set to nil")
			}
			if !parents.Contains(*mg.ParentId) {
				continue
			}
			if err := arch.addMgFromProcessor(mg, az); err != nil {
				return fmt.Errorf("architectureRecursion: error adding management group %s: %w", mg.Id, err)
			}
			parentFound = true
		default:
			continue
		}
		if !parentFound {
			return fmt.Errorf("architectureRecursion: management group %s has no valid parent", mg.Id)
		}
		newParents.Add(mg.Id)
	}
	if newParents.Cardinality() > 0 {
		return architectureRecursion(newParents, libArch, arch, az, depth+1)
	}
	return nil
}

// FetchAzureLandingZonesLibraryByTag is a convenience function to fetch the Azure Landing Zones library by member and tag.
// It calls FetchLibraryByGetterString with the appropriate URL.
// The destination directory will be appended to the .alzlib directory in the current working directory.
// To fetch the ALZ reference, supply "platform/alz" as the member, with the tag (2024.03.03).
func FetchAzureLandingZonesLibraryMember(ctx context.Context, member, tag, dst string) (fs.FS, error) {
	tag = fmt.Sprintf("platform/alz/%s", tag)
	q := url.Values{}
	q.Add("depth", "1")
	q.Add("ref", tag)
	u := fmt.Sprintf("github.com/Azure/Azure-Landing-Zones-Library//%s?%s", member, q.Encode())
	return FetchLibraryByGetterString(ctx, u, dst)
}

// FetchLibraryByGetterString fetches a library from a URL using the go-getter library.
// The caller must supply a valid go-getter URL and a destination directory, which will eb appended to
// the .alzlib directory in the current working directory.
// It returns an fs.FS interface to the fetched library to be used in the AlzLib.Init() method.
func FetchLibraryByGetterString(ctx context.Context, getterString, dstDir string) (fs.FS, error) {
	if !validDstDir(dstDir) {
		return nil, errors.New("FetchLibraryByGetterString: invalid destination directory")
	}
	dst := filepath.Join(".alzlib", dstDir)
	client := getter.Client{}
	wd, _ := os.Getwd()
	_ = os.RemoveAll(dst)
	req := &getter.Request{
		Src: getterString,
		Dst: dst,
		Pwd: wd,
	}
	_, err := client.Get(ctx, req)
	if err != nil {
		return nil, err
	}
	return os.DirFS(dst), nil
}

func validDstDir(dst string) bool {
	re := regexp.MustCompile(`^\w+$`)
	return re.MatchString(dst)
}
