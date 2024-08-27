// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"fmt"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/tools/checker"
	mapset "github.com/deckarep/golang-set/v2"
)

var CheckAllDefinitionsAreReferenced = checker.NewValidatorCheck("All definitions are referenced", checkAllDefinitionsAreReferenced)

func checkAllDefinitionsAreReferenced(azany any) error {
	az, ok := azany.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: expected *alzlib.AlzLib, got %T", azany)
	}
	// Test if we have policy (set) definitions that are not referenced by any archetype
	referencedPds := mapset.NewThreadUnsafeSet[string]()
	referencedPsds := mapset.NewThreadUnsafeSet[string]()
	referencedRds := mapset.NewThreadUnsafeSet[string]()
	for _, archetypeName := range az.Archetypes() {
		archetype := az.Archetype(archetypeName) // nolint: errcheck
		referencedPds = referencedPds.Union(archetype.PolicyDefinitions)
		referencedPsds = referencedPsds.Union(archetype.PolicySetDefinitions)
		referencedRds = referencedRds.Union(archetype.RoleDefinitions)
	}
	unreferencedPds := mapset.NewThreadUnsafeSet(az.PolicyDefinitions()...).Difference(referencedPds).ToSlice()
	unreferencedPsds := mapset.NewThreadUnsafeSet(az.PolicySetDefinitions()...).Difference(referencedPsds).ToSlice()
	unreferencedRds := mapset.NewThreadUnsafeSet(az.RoleDefinitions()...).Difference(referencedRds).ToSlice()
	if len(unreferencedPds) > 0 || len(unreferencedPsds) > 0 || len(unreferencedRds) > 0 {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: found unreferenced definitions [policyDefinitions] [policySetDefinitions] [roleDefinitions]: %v, %v, %v", unreferencedPds, unreferencedPsds, unreferencedRds)
	}
	return nil
}
