// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package checks

import (
	"fmt"

	"github.com/Azure/alzlib"
	"github.com/Azure/alzlib/internal/tools/checker"
	mapset "github.com/deckarep/golang-set/v2"
)

func CheckAllDefinitionsAreReferenced(inputs ...any) checker.ValidatorCheck {
	return checker.NewValidatorCheck(
		"All definitions are referenced",
		func() error {
			if len(inputs) != 1 {
				return fmt.Errorf("checkAllDefinitionsAreReferenced: expected 1 input, got %d", len(inputs))
			}
			return checkAllDefinitionsAreReferenced(inputs[0])
		},
	)
}

func checkAllDefinitionsAreReferenced(input any) error {
	az, ok := input.(*alzlib.AlzLib)
	if !ok {
		return fmt.Errorf("checkAllDefinitionsAreReferenced: expected *alzlib.AlzLib, got %T", input)
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
