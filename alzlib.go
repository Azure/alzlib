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

	"github.com/Azure/alzlib/processor"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/mitchellh/copystructure"
	"golang.org/x/sync/errgroup"
)

const (
	defaultParallelism = 10 // default number of parallel requests to make to Azure APIs
)

// AlzLib is the structure that gets built from the the library files
// do not create this directly, use NewAlzLib instead.
// Note: this is not thread safe, and should not be used concurrently without an external mutex.
type AlzLib struct {
	Options    *AlzLibOptions
	Deployment *DeploymentType // Deployment is the deployment object that stores the management group hierarchy

	archetypes           map[string]*Archetype
	policyAssignments    map[string]*armpolicy.Assignment
	policyDefinitions    map[string]*armpolicy.Definition
	policySetDefinitions map[string]*armpolicy.SetDefinition
	roleDefinitions      map[string]*armauthorization.RoleDefinition
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
	PolicyDefinitions     mapset.Set[string]
	PolicyAssignments     mapset.Set[string]
	PolicySetDefinitions  mapset.Set[string]
	RoleDefinitions       mapset.Set[string]
	wellKnownPolicyValues *WellKnownPolicyValues // options are used to populate the Archetype with well known parameter values
	name                  string
}

// WellKnownPolicyValues represents options for a deployment
// These are values that are typically replaced in the deployed resources
// E.g. location, log analytics workspace ID, etc.
type WellKnownPolicyValues struct {
	DefaultLocation                *string
	DefaultLogAnalyticsWorkspaceId *string
	PrivateDnsZoneResourceGroupId  *string // PrivateDnsZoneResourceGroupId is used in the Deploy-Private-Dns-Zones policy assignment
}

type AlzManagementGroupAddRequest struct {
	Id               string
	DisplayName      string
	ParentId         string
	ParentIsExternal bool
	Archetype        *Archetype
}

// NewAlzLib returns a new instance of the alzlib library, optionally using the supplied directory
// for additional policy (set) definitions.
func NewAlzLib() *AlzLib {
	az := &AlzLib{
		Options:    getDefaultAlzLibOptions(),
		archetypes: make(map[string]*Archetype),
		Deployment: &DeploymentType{
			mgs: make(map[string]*AlzManagementGroup),
		},
		policyAssignments:    make(map[string]*armpolicy.Assignment),
		policyDefinitions:    make(map[string]*armpolicy.Definition),
		policySetDefinitions: make(map[string]*armpolicy.SetDefinition),
		roleDefinitions:      make(map[string]*armauthorization.RoleDefinition),
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
func (az *AlzLib) CopyArchetype(name string, wkpv *WellKnownPolicyValues) (*Archetype, error) {
	if arch, ok := az.archetypes[name]; ok {
		rtn := new(Archetype)
		*rtn = *arch
		rtn.PolicyAssignments = arch.PolicyAssignments.Clone()
		rtn.PolicyDefinitions = arch.PolicyDefinitions.Clone()
		rtn.PolicySetDefinitions = arch.PolicySetDefinitions.Clone()
		rtn.RoleDefinitions = arch.RoleDefinitions.Clone()
		rtn.wellKnownPolicyValues = wkpv
		return rtn, nil
	}
	return nil, fmt.Errorf("archetype %s not found", name)
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

// AddManagementGroupToDeployment adds a management group to the deployment, with a parent if specified.
// If the parent is not specified, the management group is considered the root of the hierarchy.
// The archetype should have been obtained using the `AlzLib.CopyArchetype` method, together with the `WellKnownPolicyValues`.
// This allows for customization and ensures the correct policy assignment values have been set.
func (az *AlzLib) AddManagementGroupToDeployment(ctx context.Context, req AlzManagementGroupAddRequest) error {
	if req.Archetype.wellKnownPolicyValues == nil {
		return errors.New("archetype well known values not set, use Alzlib.CopyArchetype() to get a copy and update")
	}

	if _, exists := az.Deployment.mgs[req.Id]; exists {
		return fmt.Errorf("management group %s already exists", req.Id)
	}
	alzmg := newAlzManagementGroup()

	alzmg.name = req.Id
	alzmg.displayName = req.DisplayName
	alzmg.children = mapset.NewSet[*AlzManagementGroup]()
	if req.ParentIsExternal {
		if _, ok := az.Deployment.mgs[req.ParentId]; ok {

			return fmt.Errorf("external parent management group set, but already exists %s", req.ParentId)
		}
		alzmg.parentExternal = to.Ptr[string](req.ParentId)
	}
	if !req.ParentIsExternal && req.ParentId != "" {
		mg, ok := az.Deployment.mgs[req.ParentId]
		if !ok {
			return fmt.Errorf("parent management group not found %s", req.ParentId)
		}
		alzmg.parent = mg
		az.Deployment.mgs[req.ParentId].children.Add(alzmg)
	}

	// We only allow one intermediate root management group, so check if this is the first one.
	if req.ParentIsExternal {
		for mgname, mg := range az.Deployment.mgs {
			if mg.parentExternal != nil {
				return fmt.Errorf("multiple root management groups: %s and %s", mgname, req.Id)
			}
		}
	}

	// Get the policy definitions and policy set definitions referenced by the policy assignments.
	assignedPolicyDefinitionIds := mapset.NewThreadUnsafeSet[string]()
	for pa := range req.Archetype.PolicyAssignments.Iter() {
		if !az.PolicyAssignmentExists(pa) {
			return fmt.Errorf("policy assignment %s referenced in archetype %s does not exist in the library", pa, req.Archetype.name)
		}
		assignedPolicyDefinitionIds.Add(*az.policyAssignments[pa].Properties.PolicyDefinitionID)
	}

	if err := az.GetDefinitionsFromAzure(ctx, assignedPolicyDefinitionIds.ToSlice()); err != nil {
		return err
	}

	// make copies of the archetype resources for modification in the Deployment management group.
	for name := range req.Archetype.PolicyDefinitions.Iter() {
		src := az.policyDefinitions[name]
		cpy, err := copystructure.Copy(src)
		if err != nil {
			return err
		}
		newDef, ok := cpy.(*armpolicy.Definition)
		if !ok {
			return fmt.Errorf("error copying policy definition %s", name)
		}
		alzmg.policyDefinitions[name] = newDef
	}
	for name := range req.Archetype.PolicySetDefinitions.Iter() {
		src := az.policySetDefinitions[name]
		cpy, err := copystructure.Copy(src)
		if err != nil {
			return err
		}
		newSetDef, ok := cpy.(*armpolicy.SetDefinition)
		if !ok {
			return fmt.Errorf("error copying policy set definition %s", name)
		}
		alzmg.policySetDefinitions[name] = newSetDef
	}
	for name := range req.Archetype.PolicyAssignments.Iter() {
		src := az.policyAssignments[name]
		cpy, err := copystructure.Copy(src)
		if err != nil {
			return err
		}
		newpolassign, ok := cpy.(*armpolicy.Assignment)
		if !ok {
			return fmt.Errorf("error copying policy assignment %s", name)
		}
		alzmg.policyAssignments[name] = newpolassign
	}
	for name := range req.Archetype.RoleDefinitions.Iter() {
		src := az.roleDefinitions[name]
		cpy, err := copystructure.Copy(src)
		if err != nil {
			return err
		}
		newroledef, ok := cpy.(*armauthorization.RoleDefinition)
		if !ok {
			return fmt.Errorf("error copying role definition %s", name)
		}
		alzmg.roleDefinitions[name] = newroledef
	}
	alzmg.wkpv = req.Archetype.wellKnownPolicyValues

	// add the management group to the deployment.
	az.Deployment.mgs[req.Id] = alzmg

	// run Update to change all refs, etc.
	if err := az.Deployment.mgs[req.Id].update(az, nil); err != nil {
		return err
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
		switch strings.ToLower(lastButOneSegment(pd)) {
		case "policydefinitions":
			if !az.PolicyDefinitionExists(lastSegment(pd)) {
				policyDefsToGet.Add(lastSegment(pd))
			}
		case "policysetdefinitions":
			// If the set is not present, OR if the set contains referenced definitions that are not present
			// add it to the list of set defs to get.
			psd, exists := az.policySetDefinitions[lastSegment(pd)]
			if exists {
				for _, ref := range psd.Properties.PolicyDefinitions {
					if ref.PolicyDefinitionID == nil {
						return fmt.Errorf("policy set definition %s has a nil policy definition ID", *psd.Name)
					}
					if _, exists := az.policyDefinitions[lastSegment(*ref.PolicyDefinitionID)]; !exists {
						policyDefsToGet.Add(lastSegment(*ref.PolicyDefinitionID))
					}
				}
			} else {
				policySetDefsToGet.Add(lastSegment(pd))
			}

		default:
			return fmt.Errorf("unexpected policy definition type when processing assignments: %s", pd)
		}
	}

	// Add the referenced built-in definitions and set definitions to the AlzLib struct
	// so that we can use the data to determine the correct role assignments at scope.
	if policyDefsToGet.Cardinality() != 0 {
		if err := az.getBuiltInPolicies(ctx, policyDefsToGet.ToSlice()); err != nil {
			return err
		}
	}
	if policySetDefsToGet.Cardinality() != 0 {
		if err := az.getBuiltInPolicySets(ctx, policySetDefsToGet.ToSlice()); err != nil {
			return err
		}
	}
	return nil
}

// getBuiltInPolicies retrieves the built-in policy definitions with the given names
// and adds them to the AlzLib struct.
func (az *AlzLib) getBuiltInPolicies(ctx context.Context, names []string) error {
	if az.clients.policyClient == nil {
		return errors.New("policy client not set")
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
				return err
			}
			az.policyDefinitions[name] = &resp.Definition
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
		return errors.New("policy client not set")
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
				return err
			}
			// Add set definition to the AlzLib.
			az.policySetDefinitions[name] = &resp.SetDefinition
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
		for _, ref := range az.policySetDefinitions[name].Properties.PolicyDefinitions {
			defnames = append(defnames, lastSegment(*ref.PolicyDefinitionID))
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
			return fmt.Errorf("policy definition %s already exists in the library", k)
		}
		az.policyDefinitions[k] = v
	}
	for k, v := range res.PolicySetDefinitions {
		if _, exists := az.policySetDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("policy definition %s already exists in the library", k)
		}
		az.policySetDefinitions[k] = v
	}
	for k, v := range res.PolicyAssignments {
		if _, exists := az.policyAssignments[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("policy assignment %s already exists in the library", k)
		}
		az.policyAssignments[k] = v
	}
	for k, v := range res.RoleDefinitions {
		if _, exists := az.roleDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("role definition %s already exists in the library", k)
		}
		az.roleDefinitions[k] = v
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
			return fmt.Errorf("archetype %s already exists in the library", v.Name)
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
				return fmt.Errorf("error processing archetype %s, policy definition %s does not exist in the library", k, pd)
			}
			arch.PolicyDefinitions.Add(pd)
		}
		for psd := range v.PolicySetDefinitions.Iter() {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf("error processing archetype %s, policy set definition %s does not exist in the library", k, psd)
			}
			arch.PolicySetDefinitions.Add(psd)
		}
		for pa := range v.PolicyAssignments.Iter() {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf("error processing archetype %s, policy assignment %s does not exist in the library", k, pa)
			}
			arch.PolicyAssignments.Add(pa)
		}
		for rd := range v.RoleDefinitions.Iter() {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf("error processing archetype %s, role definition %s does not exist in the library", k, rd)
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
			return fmt.Errorf("error processing override archetype %s - it already exists in the library", name)
		}
		base, exists := az.archetypes[ovr.BaseArchetype]
		if !exists {
			return fmt.Errorf("error processing override archetype %s - base archetype %s does not exist in the library", name, ovr.BaseArchetype)
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

// lastSegment returns the last segment of a string separated by "/".
func lastSegment(s string) string {
	parts := strings.Split(s, "/")
	if len(parts) <= 1 {
		return "s"
	}
	return parts[len(parts)-1]
}

// lastButOneSegment returns the last but one segment of a string separated by "/".
func lastButOneSegment(s string) string {
	parts := strings.Split(s, "/")
	if len(parts) <= 2 {
		return "s"
	}
	return parts[len(parts)-2]
}
