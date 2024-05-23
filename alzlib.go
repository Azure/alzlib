// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/processor"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/brunoga/deep"
	mapset "github.com/deckarep/golang-set/v2"

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

	archetypes           map[string]*Archetype
	policyAssignments    map[string]*assets.PolicyAssignment
	policyDefinitions    map[string]*assets.PolicyDefinition
	policySetDefinitions map[string]*assets.PolicySetDefinition
	roleDefinitions      map[string]*assets.RoleDefinition
	clients              *azureClients
	mu                   sync.RWMutex // mu is a mutex to concurrency protect the AlzLib maps (not the Deployment maps, which are protected by the Deployment mutex)
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

// Archetype represents an archetype definition that hasn't been assigned to a management group
// The contents of the sets represent the map keys of the corresponding AlzLib maps.
type Archetype struct {
	PolicyDefinitions    mapset.Set[string]
	PolicyAssignments    mapset.Set[string]
	PolicySetDefinitions mapset.Set[string]
	RoleDefinitions      mapset.Set[string]
	name                 string
}

// NewAlzLib returns a new instance of the alzlib library, optionally using the supplied directory
// for additional policy (set) definitions.
func NewAlzLib(opts *AlzLibOptions) *AlzLib {
	if opts == nil {
		opts = getDefaultAlzLibOptions()
	}
	az := &AlzLib{
		Options:              opts,
		archetypes:           make(map[string]*Archetype),
		policyAssignments:    make(map[string]*assets.PolicyAssignment),
		policyDefinitions:    make(map[string]*assets.PolicyDefinition),
		policySetDefinitions: make(map[string]*assets.PolicySetDefinition),
		roleDefinitions:      make(map[string]*assets.RoleDefinition),
		clients:              new(azureClients),
		mu:                   sync.RWMutex{},
	}
	return az
}

func getDefaultAlzLibOptions() *AlzLibOptions {
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
		copy, err := deep.Copy(pa)
		if err != nil {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: error making deep copy of policy assignment %s: %w", *pa.Name, err)
		}
		az.policyAssignments[*pa.Name] = copy
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
		copy, err := deep.Copy(pd)
		if err != nil {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: error making deep copy of policy definition %s: %w", *pd.Name, err)
		}
		az.policyDefinitions[*pd.Name] = copy
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
		copy, err := deep.Copy(psd)
		if err != nil {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: error making deep copy of policy set definition %s: %w", *psd.Name, err)
		}
		az.policySetDefinitions[*psd.Name] = copy
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
		copy, err := deep.Copy(rd)
		if err != nil {
			return fmt.Errorf("Alzlib.AddPolicyAssignments: error making deep copy of role definition %s: %w", *rd.Name, err)
		}
		az.roleDefinitions[*rd.Name] = copy
	}
	return nil
}

// ListArchetypes returns a list of the archetypes in the AlzLib struct.
func (az *AlzLib) ListArchetypes() []string {
	result := make([]string, 0, len(az.archetypes))
	for k := range az.archetypes {
		result = append(result, k)
	}
	return result
}

// CopyArchetype returns a copy of the requested archetype by name.
// The returned struct can be used as a parameter to the Deployment.AddManagementGroup method.
func (az *AlzLib) CopyArchetype(name string) (*Archetype, error) {
	if arch, ok := az.archetypes[name]; ok {
		rtn := new(Archetype)
		*rtn = *arch
		rtn.PolicyAssignments = arch.PolicyAssignments.Clone()
		rtn.PolicyDefinitions = arch.PolicyDefinitions.Clone()
		rtn.PolicySetDefinitions = arch.PolicySetDefinitions.Clone()
		rtn.RoleDefinitions = arch.RoleDefinitions.Clone()
		return rtn, nil
	}
	return nil, fmt.Errorf("Alzlib.CopyArchetype: archetype %s not found", name)
}

// PolicyDefinitionExists returns true if the policy definition exists in the AlzLib struct.
func (az *AlzLib) PolicyDefinitionExists(name string) bool {
	_, exists := az.policyDefinitions[name]
	return exists
}

// PolicySetDefinitionExists returns true if the policy set definition exists in the AlzLib struct.
func (az *AlzLib) PolicySetDefinitionExists(name string) bool {
	_, exists := az.policySetDefinitions[name]
	return exists
}

// PolicyAssignmentExists returns true if the policy assignment exists in the AlzLib struct.
func (az *AlzLib) PolicyAssignmentExists(name string) bool {
	_, exists := az.policyAssignments[name]
	return exists
}

// RoleDefinitionExists returns true if the role definition exists in the AlzLib struct.
func (az *AlzLib) RoleDefinitionExists(name string) bool {
	_, exists := az.roleDefinitions[name]
	return exists
}

// GetPolicyDefinition returns a deep copy of the requested policy definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) GetPolicyDefinition(name string) (*assets.PolicyDefinition, error) {
	if pd, exists := az.policyDefinitions[name]; exists {
		return deep.Copy(pd)
	}
	return nil, fmt.Errorf("Alzlib.GetPolicyDefinition: policy definition %s not found", name)
}

// GetPolicySetDefinition returns a deep copy of the requested policy set definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) GetPolicyAssignment(name string) (*assets.PolicyAssignment, error) {
	if pa, exists := az.policyAssignments[name]; exists {
		return deep.Copy(pa)
	}
	return nil, fmt.Errorf("Alzlib.GetPolicyAssignment: policy assignment %s not found", name)
}

// GetPolicySetDefinition returns a deep copy of the requested policy set definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) GetPolicySetDefinition(name string) (*assets.PolicySetDefinition, error) {
	if psd, exists := az.policySetDefinitions[name]; exists {
		return deep.Copy(psd)
	}
	return nil, fmt.Errorf("Alzlib.GetPolicySetDefinition: policy set definition %s not found", name)
}

// GetRoleDefinition returns a deep copy of the requested role definition.
// This is safe to modify without affecting the original.
func (az *AlzLib) GetRoleDefinition(name string) (*assets.RoleDefinition, error) {
	if rd, exists := az.roleDefinitions[name]; exists {
		return deep.Copy(rd)
	}
	return nil, fmt.Errorf("Alzlib.GetRoleDefinition: role definition %s not found", name)
}

// AddPolicyClient adds an authenticated *armpolicy.ClientFactory to the AlzLib struct.
// This is needed to get policy objects from Azure.
func (az *AlzLib) AddPolicyClient(client *armpolicy.ClientFactory) {
	az.clients.policyClient = client
}

// Init processes ALZ libraries, supplied as fs.FS interfaces.
// These are typically the embed.FS global var `Lib`, or an `os.DirFS`.
// It populates the struct with the results of the processing.
func (az *AlzLib) Init(ctx context.Context, libs ...fs.FS) error {
	if az.Options == nil || az.Options.Parallelism == 0 {
		return errors.New("alzlib Options not set or parallelism is 0")
	}

	// Process the libraries
	for _, lib := range libs {
		res := new(processor.Result)
		pc := processor.NewProcessorClient(lib)
		if err := pc.Process(res); err != nil {
			return fmt.Errorf("error processing library %v: %w", lib, err)
		}

		// Put results into the AlzLib.
		if err := az.addProcessedResult(res); err != nil {
			return err
		}

		// Generate archetypes
		if err := az.generateArchetypes(res); err != nil {
			return err
		}

		// Generate override archetypes
		if err := az.generateOverrideArchetypes(res); err != nil {
			return err
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
			psd, exists := az.policySetDefinitions[resId.Name]
			if exists {
				pdrefs, err := psd.GetPolicyDefinitionReferences()
				if err != nil {
					return fmt.Errorf("Alzlib.GetDefinitionsFromAzure: error getting policy definition references for policy set definition %s: %w", pd, err)
				}
				for _, ref := range pdrefs {
					subResId, err := arm.ParseResourceID(*ref.PolicyDefinitionID)
					if err != nil {
						return fmt.Errorf("policy set definition %s has a nil policy definition ID", *psd.Name)
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
				return fmt.Errorf("Alzlib.getBuiltInPolicies: error getting built-in policy definition %s: %w", name, err)
			}
			az.policyDefinitions[name] = assets.NewPolicyDefinition(resp.Definition)
			return nil
		})
	}
	if err := grp.Wait(); err != nil {
		return err
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
				return fmt.Errorf("Alzlib.getBuiltInPolicySets: error getting built-in policy set definition %s: %w", name, err)
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
		return err
	}

	// Get the policy definitions for newly added policy set definitions.
	defnames := make([]string, 0)
	for _, name := range names {
		name := name
		refs, err := az.policySetDefinitions[name].GetPolicyDefinitionReferences()
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
		return err
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
	if _, exists := res.LibArchetypes["empty"]; !exists {
		res.LibArchetypes["empty"] = &processor.LibArchetype{
			Name:                 "empty",
			PolicyAssignments:    mapset.NewThreadUnsafeSet[string](),
			PolicyDefinitions:    mapset.NewThreadUnsafeSet[string](),
			PolicySetDefinitions: mapset.NewThreadUnsafeSet[string](),
			RoleDefinitions:      mapset.NewThreadUnsafeSet[string](),
		}
	}

	// generate alzlib archetypes.
	for k, v := range res.LibArchetypes {
		if _, exists := az.archetypes[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("Alzlib.generateArchetypes: archetype %s already exists in the library", v.Name)
		}
		arch := &Archetype{
			PolicyDefinitions:    mapset.NewSet[string](),
			PolicyAssignments:    mapset.NewSet[string](),
			PolicySetDefinitions: mapset.NewSet[string](),
			RoleDefinitions:      mapset.NewSet[string](),
			name:                 v.Name,
		}
		for pd := range v.PolicyDefinitions.Iter() {
			if _, ok := az.policyDefinitions[pd]; !ok {
				return fmt.Errorf("Alzlib.generateArchetypes: error processing archetype %s, policy definition %s does not exist in the library", k, pd)
			}
			arch.PolicyDefinitions.Add(pd)
		}
		for psd := range v.PolicySetDefinitions.Iter() {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf("Alzlib.generateArchetypes: error processing archetype %s, policy set definition %s does not exist in the library", k, psd)
			}
			arch.PolicySetDefinitions.Add(psd)
		}
		for pa := range v.PolicyAssignments.Iter() {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf("Alzlib.generateArchetypes: error processing archetype %s, policy assignment %s does not exist in the library", k, pa)
			}
			arch.PolicyAssignments.Add(pa)
		}
		for rd := range v.RoleDefinitions.Iter() {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf("Alzlib.generateArchetypes: error processing archetype %s, role definition %s does not exist in the library", k, rd)
			}
			arch.RoleDefinitions.Add(rd)
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
		newArch := &Archetype{
			PolicyDefinitions:    base.PolicyDefinitions.Clone().Union(ovr.PolicyDefinitionsToAdd).Difference(ovr.PolicyDefinitionsToRemove),
			PolicySetDefinitions: base.PolicySetDefinitions.Clone().Union(ovr.PolicySetDefinitionsToAdd).Difference(ovr.PolicySetDefinitionsToRemove),
			PolicyAssignments:    base.PolicyAssignments.Clone().Union(ovr.PolicyAssignmentsToAdd).Difference(ovr.PolicyAssignmentsToRemove),
			RoleDefinitions:      base.RoleDefinitions.Clone().Union(ovr.RoleDefinitionsToAdd).Difference(ovr.RoleDefinitionsToRemove),
			name:                 name,
		}
		az.archetypes[name] = newArch
	}
	return nil
}
