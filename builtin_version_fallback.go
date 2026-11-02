// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// The built-in version listing of a definition (GET .../policy[Set]Definitions/{name}/versions) has
// been seen to omit the versions of a definition that has them, or to list them under another name
// (Azure/Azure-Landing-Zones#4327). When the listing provides no version satisfying the requested
// constraint, the versions are got from the definition itself instead: the definition lists all its
// versions in properties.versions, and each version can be got on its own. The fallback stores what the
// listing would have led to: every version of a definition referenced by a built-in policy set, as
// fetchReferencedPolicyDefinitionVersions stores every listed version, and only the selected version
// otherwise. This only happens when the listing fails, so a healthy listing costs no additional request.

// versionListing records what the built-in version listing of a definition returned. It decides which
// listed versions belong to the requested definition, and describes the listing in the error returned
// when no version satisfies the requested constraint.
type versionListing struct {
	name     string   // requested definition name
	versions []string // versions listed under the requested name
	ignored  []string // <name>@<version> listed under another definition name
}

// accept reports whether a listed version belongs to the requested definition, and returns the name
// to store it under. A listed version is named after its resource ID, but definitions are stored and
// looked up by name, case-sensitively: a version listed under the requested name in another case is
// stored under the requested name. Versions of other definitions are not used.
func (l *versionListing) accept(name, version *string) (*string, bool) {
	if name == nil || !strings.EqualFold(*name, l.name) {
		l.ignored = append(l.ignored, JoinNameAndVersion(to.ValOrZero(name), version))
		return nil, false
	}

	l.versions = append(l.versions, to.ValOrZero(version))

	return to.Ptr(l.name), true
}

// notFound returns the error for a constraint that neither the listing nor the definition satisfies.
// err is the error for the listing, fallbackErr the error getting the version from the definition.
func (l *versionListing) notFound(err, fallbackErr error) error {
	listing := fmt.Sprintf("version listing of `%s`: versions %v", l.name, l.versions)
	if len(l.ignored) > 0 {
		listing += fmt.Sprintf(", ignored versions of other definitions %v", l.ignored)
	}

	return errors.Join(
		err,
		errors.New(listing),
		fmt.Errorf("getting the version from the definition instead: %w", fallbackErr),
	)
}

// resolvePolicyDefinitionVersion returns the listed policy definition version that satisfies
// constraint or, if the listing has none, the version got from the definition itself.
func (az *AlzLib) resolvePolicyDefinitionVersion(
	ctx context.Context,
	listed *assets.PolicyDefinitionVersions,
	listing *versionListing,
	constraint *string,
) (*assets.PolicyDefinition, error) {
	pd, err := listed.GetVersion(constraint)
	if constraint == nil || !errors.Is(err, assets.ErrNoVersionFound) {
		return pd, err
	}

	pd, fallbackErr := az.builtInPolicyDefinitionVersion(ctx, listing.name, *constraint)
	if fallbackErr != nil {
		return nil, listing.notFound(err, fallbackErr)
	}

	return pd, nil
}

// resolvePolicySetDefinitionVersion returns the listed policy set definition version that satisfies
// constraint or, if the listing has none, the version got from the definition itself.
func (az *AlzLib) resolvePolicySetDefinitionVersion(
	ctx context.Context,
	listed *assets.PolicySetDefinitionVersions,
	listing *versionListing,
	constraint *string,
) (*assets.PolicySetDefinition, error) {
	psd, err := listed.GetVersion(constraint)
	if constraint == nil || !errors.Is(err, assets.ErrNoVersionFound) {
		return psd, err
	}

	psd, fallbackErr := az.builtInPolicySetDefinitionVersion(ctx, listing.name, *constraint)
	if fallbackErr != nil {
		return nil, listing.notFound(err, fallbackErr)
	}

	return psd, nil
}

// addBuiltInPolicyDefinitionVersions adds every version of the built-in policy definition name, got from
// the definition itself, provided one satisfies constraint. It stands in for the version listing of a
// definition referenced by a built-in policy set, which adds every listed version: adding only the version
// that satisfies constraint would let a later reference with a broader constraint, which
// PolicyDefinitionExists then finds satisfied, resolve to an older version than with a healthy listing.
// Versions already stored are not got again, and nothing is added unless every version is got.
func (az *AlzLib) addBuiltInPolicyDefinitionVersions(ctx context.Context, name, constraint string) error {
	policyClient, err := az.builtInPolicyClient(ctx)
	if err != nil {
		return err
	}

	_, versions, err := selectBuiltInPolicyDefinitionVersion(ctx, policyClient, name, constraint)
	if err != nil {
		return err
	}

	pds := make([]*assets.PolicyDefinition, 0, len(versions))

	for _, version := range versions {
		if az.storedPolicyDefinitionVersion(name, version) {
			continue
		}

		pd, err := getBuiltInPolicyDefinitionVersion(ctx, policyClient, name, version)
		if err != nil {
			return err
		}

		pds = append(pds, pd)
	}

	if err := az.AddPolicyDefinitions(pds...); err != nil {
		return fmt.Errorf("adding versions of built-in policy definition `%s`: %w", name, err)
	}

	return nil
}

// storedPolicyDefinitionVersion reports whether exactly version of the policy definition name is stored.
func (az *AlzLib) storedPolicyDefinitionVersion(name, version string) bool {
	az.mu.RLock()
	defer az.mu.RUnlock()

	pdvs, ok := az.policyDefinitions[name]

	return ok && pdvs != nil && pdvs.Exists(&version)
}

// builtInPolicyClient returns the policy client, unless ctx is done.
func (az *AlzLib) builtInPolicyClient(ctx context.Context) (*armpolicy.ClientFactory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	az.mu.RLock()
	policyClient := az.clients.policyClient
	az.mu.RUnlock()

	if policyClient == nil {
		return nil, errors.New("policy client not set")
	}

	return policyClient, nil
}

// builtInPolicyDefinitionVersion gets the version of the built-in policy definition name that satisfies
// constraint, as selected by selectBuiltInPolicyDefinitionVersion.
func (az *AlzLib) builtInPolicyDefinitionVersion(
	ctx context.Context,
	name, constraint string,
) (*assets.PolicyDefinition, error) {
	policyClient, err := az.builtInPolicyClient(ctx)
	if err != nil {
		return nil, err
	}

	version, _, err := selectBuiltInPolicyDefinitionVersion(ctx, policyClient, name, constraint)
	if err != nil {
		return nil, err
	}

	return getBuiltInPolicyDefinitionVersion(ctx, policyClient, name, version)
}

// selectBuiltInPolicyDefinitionVersion gets the built-in policy definition name and returns, among the
// versions it lists, the one that GetVersion selects for constraint, and all of them.
func selectBuiltInPolicyDefinitionVersion(
	ctx context.Context,
	policyClient *armpolicy.ClientFactory,
	name, constraint string,
) (selected string, versions []string, err error) {
	def, err := policyClient.NewDefinitionsClient().GetBuiltIn(ctx, name, nil)
	if err != nil {
		return "", nil, fmt.Errorf("getting built-in policy definition `%s`: %w", name, err)
	}

	var candidates []*string
	if def.Properties != nil {
		candidates = append(candidates, def.Properties.Versions...)
		candidates = append(candidates, def.Properties.Version)
	}

	selected, versions, err = selectVersion(assets.NewPolicyDefinitionVersions(), candidates, constraint,
		func(v *string) *assets.PolicyDefinition {
			return assets.NewPolicyDefinition(armpolicy.Definition{
				Name:       to.Ptr(name),
				Properties: &armpolicy.DefinitionProperties{Version: v},
			})
		},
	)
	if err != nil {
		return "", nil, fmt.Errorf("built-in policy definition `%s`: %w", name, err)
	}

	return selected, versions, nil
}

// getBuiltInPolicyDefinitionVersion gets version of the built-in policy definition name, named name.
func getBuiltInPolicyDefinitionVersion(
	ctx context.Context,
	policyClient *armpolicy.ClientFactory,
	name, version string,
) (*assets.PolicyDefinition, error) {
	resp, err := policyClient.NewDefinitionVersionsClient().GetBuiltIn(ctx, name, version, nil)
	if err != nil {
		return nil, fmt.Errorf("getting built-in policy definition `%s`: %w", JoinNameAndVersion(name, &version), err)
	}

	pd, err := assets.NewPolicyDefinitionFromVersionValidate(resp.DefinitionVersion)
	if err != nil {
		return nil, fmt.Errorf("validating built-in policy definition `%s`: %w", JoinNameAndVersion(name, &version), err)
	}

	if err := checkVersion(pd, name, version); err != nil {
		return nil, err
	}

	pd.Name = to.Ptr(name)

	return pd, nil
}

// builtInPolicySetDefinitionVersion gets the built-in policy set definition name, selects among the
// versions it lists the one that GetVersion selects for constraint, and gets that version.
func (az *AlzLib) builtInPolicySetDefinitionVersion(
	ctx context.Context,
	name, constraint string,
) (*assets.PolicySetDefinition, error) {
	policyClient, err := az.builtInPolicyClient(ctx)
	if err != nil {
		return nil, err
	}

	def, err := policyClient.NewSetDefinitionsClient().GetBuiltIn(ctx, name, nil)
	if err != nil {
		return nil, fmt.Errorf("getting built-in policy set definition `%s`: %w", name, err)
	}

	var versions []*string
	if def.Properties != nil {
		versions = append(versions, def.Properties.Versions...)
		versions = append(versions, def.Properties.Version)
	}

	version, _, err := selectVersion(assets.NewPolicySetDefinitionVersions(), versions, constraint,
		func(v *string) *assets.PolicySetDefinition {
			return assets.NewPolicySetDefinition(armpolicy.SetDefinition{
				Name:       to.Ptr(name),
				Properties: &armpolicy.SetDefinitionProperties{Version: v},
			})
		},
	)
	if err != nil {
		return nil, fmt.Errorf("built-in policy set definition `%s`: %w", name, err)
	}

	resp, err := policyClient.NewSetDefinitionVersionsClient().GetBuiltIn(ctx, name, version, nil)
	if err != nil {
		return nil, fmt.Errorf("getting built-in policy set definition `%s`: %w", JoinNameAndVersion(name, &version), err)
	}

	psd, err := assets.NewPolicySetDefinitionFromVersionValidate(resp.SetDefinitionVersion)
	if err != nil {
		return nil, fmt.Errorf(
			"validating built-in policy set definition `%s`: %w", JoinNameAndVersion(name, &version), err,
		)
	}

	if err := checkVersion(psd, name, version); err != nil {
		return nil, err
	}

	psd.Name = to.Ptr(name)

	return psd, nil
}

// selectVersion returns the version among versions that GetVersion selects for constraint, so that the
// version got from a definition is the one its listing would have provided, and every valid version among
// versions. The collection c is filled with placeholders, made by placeholder, that carry nothing but the
// version.
func selectVersion[T assets.Versioned](
	c *assets.VersionedPolicyCollection[T],
	versions []*string,
	constraint string,
	placeholder func(version *string) T,
) (selected string, valid []string, err error) {
	for _, v := range versions {
		if v == nil || *v == "" {
			continue
		}

		// Add fails only for a version that is not semver, which the listing would not have stored either.
		_ = c.Add(placeholder(v), false) //nolint:errcheck
	}

	got, err := c.GetVersion(&constraint)
	if err != nil {
		return "", nil, fmt.Errorf("versions %v: %w", c.Versions(), err)
	}

	for _, v := range c.Versions() {
		valid = append(valid, v.Original())
	}

	return to.ValOrZero(got.GetVersion()), valid, nil
}

// checkVersion checks that Azure returned the requested version of the definition name.
func checkVersion[T assets.Versioned](got T, name, version string) error {
	gotName := to.ValOrZero(got.GetName())
	if strings.EqualFold(gotName, name) && to.ValOrZero(got.GetVersion()) == version {
		return nil
	}

	return fmt.Errorf(
		"getting built-in definition `%s` returned `%s`",
		JoinNameAndVersion(name, &version),
		JoinNameAndVersion(gotName, got.GetVersion()),
	)
}
