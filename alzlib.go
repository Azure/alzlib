// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	sets "github.com/deckarep/golang-set/v2"
	"github.com/matt-FFFFFF/alzlib/processor"
	"github.com/matt-FFFFFF/alzlib/to"
	"golang.org/x/sync/errgroup"
)

const (
	defaultParallelism = 10 // default number of parallel requests to make to Azure APIs
)

// Embed the Lib dir into the binary.
//
//go:embed lib
var Lib embed.FS

// AlzLib is the structure that gets built from the the library files
// do not create this directly, use NewAlzLib instead.
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
	PolicyDefinitions     sets.Set[string]
	PolicyAssignments     sets.Set[string]
	PolicySetDefinitions  sets.Set[string]
	RoleDefinitions       sets.Set[string]
	wellKnownPolicyValues *WellKnownPolicyValues // options are used to populate the Archetype with well known parameter values
}

// WellKnownPolicyValues represents options for a deployment
// These are values that are typically replaced in the deployed resources
// E.g. location, log analytics workspace ID, etc.
type WellKnownPolicyValues struct {
	DefaultLocation                string
	DefaultLogAnalyticsWorkspaceId string
}

// NewAlzLib returns a new instance of the alzlib library, optionally using the supplied directory
// for additional policy (set) definitions.
func NewAlzLib() *AlzLib {
	az := &AlzLib{
		Options:    getDefaultAlzLibOptions(),
		archetypes: make(map[string]*Archetype),
		Deployment: &DeploymentType{
			mgs: make(map[string]*AlzManagementGroup),
			mu:  sync.RWMutex{},
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
	for i, lib := range libs {
		res := new(processor.Result)
		pc := processor.NewProcessorClient(lib)
		if err := pc.Process(res); err != nil {
			return fmt.Errorf("error processing library %v: %w", lib, err)
		}

		// Put results into the AlzLib.
		if err := az.addProcessedResult(res); err != nil {
			return err
		}

		// Generate archetypes from the first library.
		if i == 0 {
			if err := az.generateArchetypes(res); err != nil {
				return err
			}
		}
	}

	// Get the policy definitions and policy set definitions referenced by the policy assignments.
	assignedPolicyDefinitionIds := sets.NewSet[string]()
	for archname, arch := range az.archetypes {
		for pa := range arch.PolicyAssignments.Iter() {
			if !az.PolicyAssignmentExists(pa) {
				return fmt.Errorf("policy assignment %s referenced in archetype %s does not exist in the library", pa, archname)
			}
			assignedPolicyDefinitionIds.Add(*az.policyAssignments[pa].Properties.PolicyDefinitionID)
		}
	}

	if err := az.GetDefinitionsFromAzure(ctx, assignedPolicyDefinitionIds.ToSlice()); err != nil {
		return err
	}

	return nil
}

// AddManagementGroupToDeployment adds a management group to the deployment, with a parent if specified.
// If the parent is not specified, the management group is considered the root of the hierarchy.
// You should pass the source Archetype through the .WithWellKnownPolicyParameters() method
// to ensure that the values in the wellKnownPolicyValues are honored.
func (az *AlzLib) AddManagementGroupToDeployment(name, displayName, parent string, parentIsExternal bool, arch *Archetype) error {
	if arch.wellKnownPolicyValues == nil {
		return errors.New("archetype well known values not set, use Archetype.WithWellKnownPolicyValues() to update")
	}

	az.Deployment.mu.Lock()
	defer az.Deployment.mu.Unlock()
	if _, exists := az.Deployment.mgs[name]; exists {
		return fmt.Errorf("management group %s already exists", name)
	}
	alzmg := newAlzManagementGroup()

	alzmg.name = name
	alzmg.displayName = displayName
	alzmg.children = sets.NewSet[*AlzManagementGroup]()
	if parentIsExternal {
		if _, ok := az.Deployment.mgs[parent]; ok {

			return fmt.Errorf("external parent management group set, but already exists %s", parent)
		}
		alzmg.parentExternal = to.Ptr[string](parent)
	}
	if !parentIsExternal && parent != "" {
		mg, ok := az.Deployment.mgs[parent]
		if !ok {
			return fmt.Errorf("parent management group not found %s", parent)
		}
		alzmg.parent = mg
		az.Deployment.mgs[parent].children.Add(alzmg)
	}

	// We only allow one intermediate root management group, so check if this is the first one.
	if parentIsExternal {
		for mgname, mg := range az.Deployment.mgs {
			if mg.parentExternal != nil {
				return fmt.Errorf("multiple root management groups: %s and %s", mgname, name)
			}
		}
	}

	// make copies of the archetype resources for modification in the Deployment management group.
	for name := range arch.PolicyDefinitions.Iter() {
		newdef := new(armpolicy.Definition)
		*newdef = *az.policyDefinitions[name]
		alzmg.policyDefinitions[name] = newdef
	}
	for name := range arch.PolicySetDefinitions.Iter() {
		newdef := new(armpolicy.SetDefinition)
		*newdef = *az.policySetDefinitions[name]
		alzmg.policySetDefinitions[name] = newdef
	}
	for name := range arch.PolicyAssignments.Iter() {
		newpolassign := new(armpolicy.Assignment)
		*newpolassign = *az.policyAssignments[name]
		alzmg.policyAssignments[name] = newpolassign
	}
	for name := range arch.RoleDefinitions.Iter() {
		newroledef := new(armauthorization.RoleDefinition)
		*newroledef = *az.roleDefinitions[name]
		alzmg.roleDefinitions[name] = newroledef
	}
	alzmg.wkpv = arch.wellKnownPolicyValues

	// add the management group to the deployment.
	az.Deployment.mgs[name] = alzmg

	// run Update to change all refs, etc.
	if err := az.Deployment.mgs[name].Update(az, nil); err != nil {
		return err
	}

	return nil
}

// GetDefinitionsFromAzure takes a slice of strings containing Azure resource IDs of policy definitions and policy set definitions.
// It then fetches them from Azure if needed and adds them to the AlzLib struct.
// For set definitions we need to get all of them, even if they exist in AlzLib already because they can contain built-in definitions.
func (az *AlzLib) GetDefinitionsFromAzure(ctx context.Context, pds []string) error {
	policyDefsToGet := sets.NewSet[string]()
	policySetDefsToGet := sets.NewSet[string]()
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
		if err := az.GetBuiltInPolicies(ctx, policyDefsToGet.ToSlice()); err != nil {
			return err
		}
	}
	if policySetDefsToGet.Cardinality() != 0 {
		if err := az.GetBuiltInPolicySets(ctx, policySetDefsToGet.ToSlice()); err != nil {
			return err
		}
	}
	return nil
}

// GetBuiltInPolicies retrieves the built-in policy definitions with the given names
// and adds them to the AlzLib struct.
func (az *AlzLib) GetBuiltInPolicies(ctx context.Context, names []string) error {
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

// GetBuiltInPolicySets retrieves the built-in policy set definitions with the given names
// and adds them to the AlzLib struct.
func (az *AlzLib) GetBuiltInPolicySets(ctx context.Context, names []string) error {
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
	if err := az.GetBuiltInPolicies(ctx, defnames); err != nil {
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
	if _, exists := res.LibArchetypes["empty"]; !exists {
		res.LibArchetypes["empty"] = &processor.LibArchetype{
			Name:                 "empty",
			PolicyAssignments:    make([]string, 0),
			PolicyDefinitions:    make([]string, 0),
			PolicySetDefinitions: make([]string, 0),
			RoleDefinitions:      make([]string, 0),
		}
	}

	// generate alzlib archetypes.
	for k, v := range res.LibArchetypes {
		if _, exists := az.archetypes[k]; exists {
			return fmt.Errorf("archetype %s already exists in the library", v.Name)
		}
		arch := &Archetype{
			PolicyDefinitions:    sets.NewSet[string](),
			PolicyAssignments:    sets.NewSet[string](),
			PolicySetDefinitions: sets.NewSet[string](),
			RoleDefinitions:      sets.NewSet[string](),
		}
		for _, pd := range v.PolicyDefinitions {
			if _, ok := az.policyDefinitions[pd]; !ok {
				return fmt.Errorf("error processing archetype %s, policy definition %s does not exist in the library", k, pd)
			}
			arch.PolicyDefinitions.Add(pd)
		}
		for _, psd := range v.PolicySetDefinitions {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf("error processing archetype %s, policy set definition %s does not exist in the library", k, psd)
			}
			arch.PolicySetDefinitions.Add(psd)
		}
		for _, pa := range v.PolicyAssignments {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf("error processing archetype %s, policy assignment %s does not exist in the library", k, pa)
			}
			arch.PolicyAssignments.Add(pa)
		}
		for _, rd := range v.RoleDefinitions {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf("error processing archetype %s, role definition %s does not exist in the library", k, rd)
			}
			arch.RoleDefinitions.Add(rd)
		}
		az.archetypes[v.Name] = arch
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
