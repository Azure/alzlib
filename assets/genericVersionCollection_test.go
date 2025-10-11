// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package assets

import (
	"maps"
	"testing"

	"github.com/Masterminds/semver/v3"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPolicyName      = "Test Policy"
	testVersion100      = "1.0.0"
	policyVersionedName = "PolicyVersioned"
)

func TestVersionedPolicyCollection_Add_VersionlessFirst(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := testPolicyName
	policy := fakePolicyDefinitionless(name)
	require.NoError(t, pdvs.Add(policy, false))
	assert.Equal(t, policy, pdvs.versionlessDefinition)
}

func TestVersionedPolicyCollection_Add_VersionedFirst(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := testPolicyName
	version := testVersion100
	policy := fakePolicyDefinitioned(name, version)
	require.NoError(t, pdvs.Add(policy, false))

	found := false

	for k := range maps.Keys(pdvs.versions) {
		if k.String() == version {
			found = true

			assert.Equal(t, policy, pdvs.versions[k])

			break
		}
	}

	assert.Truef(t, found, "expected version %s to be found in versions map", version)
}

func TestVersionedPolicyCollection_Add_DuplicateSemVer(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	version := testVersion100
	policy1 := fakePolicyDefinitioned("Policy1", version)
	policy2 := fakePolicyDefinitioned("Policy1", version)

	require.NoError(t, pdvs.Add(policy1, false))
	require.NoError(t, pdvs.Add(policy2, false))
	assert.Len(t, pdvs.versions, 1)
}

func TestVersionedPolicyCollection_Add_MixVersionedAndVersionless(t *testing.T) {
	version := testVersion100
	versioned := fakePolicyDefinitioned("Policy1", version)
	versionless := fakePolicyDefinitionless("Policy2")

	t.Run("versioned first", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()
		require.NoError(t, pdvs.Add(versioned, false))
		require.ErrorContains(t, pdvs.Add(versionless, false), "versioned definitions already exist")
	})

	t.Run("versionless first", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()
		require.NoError(t, pdvs.Add(versionless, false))
		require.ErrorContains(t, pdvs.Add(versioned, false), "versionless definition(s) already exists")
	})
}

func TestVersionedPolicyCollection_Add_InvalidVersionString(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := testPolicyName
	version := "not-a-semver"
	policy := fakePolicyDefinitioned(name, version)
	require.ErrorContains(t, pdvs.Add(policy, false), "invalid version string")
}

func TestVersionedPolicyCollection_Add_NilPolicyOrProperties(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	require.Error(t, pdvs.Add(nil, false))
}

func TestVersionedPolicyCollection_Add_DifferentName(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	policy1 := fakePolicyDefinitioned("Policy1", testVersion100)
	policy2 := fakePolicyDefinitioned("Policy2", "1.0.1")

	require.NoError(t, pdvs.Add(policy1, false))
	require.ErrorContains(
		t,
		pdvs.Add(policy2, false),
		"cannot add with different name than existing version.",
	)
}

func TestVersionedPolicyCollection_GetVersion_Versionless(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "PolicyVersionless"
	versionless := fakePolicyDefinitionless(name)
	require.NoError(t, pdvs.Add(versionless, false))

	t.Run("nil version constraint", func(t *testing.T) {
		got, err := pdvs.GetVersion(nil)
		require.NoError(t, err)
		assert.Equal(t, versionless, got)
	})

	t.Run("empty version constraint", func(t *testing.T) {
		empty := ""
		_, err := pdvs.GetVersion(&empty)
		require.ErrorContains(t, err, "constraint string cannot be empty")
	})

	t.Run("non-empty version constraint returns nil", func(t *testing.T) {
		ver := "1.0.*"
		got, err := pdvs.GetVersion(&ver)
		require.ErrorContains(t, err, "no version found for constraint")
		assert.Nil(t, got)
	})
}

func TestVersionedPolicyCollection_GetVersion_Versioned(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := policyVersionedName
	v1 := testVersion100
	v2 := "2.0.0"
	policy1 := fakePolicyDefinitioned(name, v1)
	policy2 := fakePolicyDefinitioned(name, v2)

	require.NoError(t, pdvs.Add(policy1, false))
	require.NoError(t, pdvs.Add(policy2, false))

	t.Run("major + minor match", func(t *testing.T) {
		got, err := pdvs.GetVersion(to.Ptr("1.0.*"))
		require.NoError(t, err)
		assert.Equal(t, policy1, got)
	})

	t.Run("latest version with wildcard constraint", func(t *testing.T) {
		constr := "1.*.*"
		got, err := pdvs.GetVersion(&constr)
		require.NoError(t, err)
		assert.Equal(t, policy1, got)
	})

	t.Run("latest version with nil constraint", func(t *testing.T) {
		got, err := pdvs.GetVersion(nil)
		require.NoError(t, err)
		assert.Equal(t, policy2, got)
	})

	t.Run("latest version with empty constraint", func(t *testing.T) {
		empty := ""
		_, err := pdvs.GetVersion(&empty)
		require.Error(t, err)
	})

	t.Run("no match for constraint", func(t *testing.T) {
		constr := "3.0.*"
		got, err := pdvs.GetVersion(&constr)
		require.ErrorContains(t, err, "no version found for constraint")
		assert.Nil(t, got)
	})

	t.Run("wildcard patch only", func(t *testing.T) {
		constr := "1.0.*"
		got, err := pdvs.GetVersion(&constr)
		require.NoError(t, err)
		assert.Equal(t, policy1, got)
	})

	t.Run("invalid wildcard major", func(t *testing.T) {
		constr := "*.*.*"
		got, err := pdvs.GetVersion(&constr)
		require.ErrorContains(t, err, "version constraint should not have wildcard in major version")
		assert.Nil(t, got)
	})

	t.Run("invalid no wildcard patch", func(t *testing.T) {
		constr := testVersion100
		got, err := pdvs.GetVersion(&constr)
		require.ErrorContains(t, err, "version constraint should have wildcard in patch version")
		assert.Nil(t, got)
	})
}

func TestVersionedPolicyCollection_GetVersion_InvalidConstraint(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := policyVersionedName
	v1 := testVersion100
	policy := fakePolicyDefinitioned(name, v1)
	require.NoError(t, pdvs.Add(policy, false))

	constr := "not-a-semver"
	got, err := pdvs.GetVersion(&constr)
	require.Error(t, err)
	assert.Nil(t, got)
}

func TestVersionedPolicyCollection_GetVersion_WildcardConstraint(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := policyVersionedName
	v1 := testVersion100
	policy := fakePolicyDefinitioned(name, v1)
	require.NoError(t, pdvs.Add(policy, false))

	constr := "1.*.0"
	got, err := pdvs.GetVersion(&constr)
	require.Error(t, err)
	assert.Nil(t, got)
}

func TestVersionedPolicyCollection_GetVersion_PrereleaseVersionMatchOnNilVersion(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := policyVersionedName
	preReleaseVersion := "1.0.0-preview"
	policy := fakePolicyDefinitioned(name, preReleaseVersion)
	require.NoError(t, pdvs.Add(policy, false))

	got, err := pdvs.GetVersion(nil)
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestVersionedPolicyCollection_Exists(t *testing.T) {
	t.Run("returns true when versionless definition present", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()
		versionless := fakePolicyDefinitionless("PolicyVersionless")
		require.NoError(t, pdvs.Add(versionless, false))

		assert.True(t, pdvs.Exists(nil))
	})

	t.Run("returns false when versionless definition missing", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()

		assert.False(t, pdvs.Exists(nil))
	})

	t.Run("returns true when exact version exists", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()
		policy := fakePolicyDefinitioned(policyVersionedName, testVersion100)
		require.NoError(t, pdvs.Add(policy, false))

		assert.True(t, pdvs.Exists(to.Ptr(testVersion100)))
	})

	t.Run("returns false when version missing", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()
		policy := fakePolicyDefinitioned(policyVersionedName, testVersion100)
		require.NoError(t, pdvs.Add(policy, false))

		missingVersion := "1.0.1"
		assert.False(t, pdvs.Exists(&missingVersion))
	})

	t.Run("returns false when version string invalid", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()
		policy := fakePolicyDefinitioned(policyVersionedName, testVersion100)
		require.NoError(t, pdvs.Add(policy, false))

		invalidVersion := "1.0.*"
		assert.False(t, pdvs.Exists(&invalidVersion))
	})

	t.Run("returns false when version string invalid with minor", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()
		policy := fakePolicyDefinitioned(policyVersionedName, testVersion100)
		require.NoError(t, pdvs.Add(policy, false))

		invalidVersion := "1.*.*"
		assert.False(t, pdvs.Exists(&invalidVersion))
	})
}

func fakePolicyDefinitioned(name string, version string) *PolicyDefinition {
	return &PolicyDefinition{
		Definition: armpolicy.Definition{
			Name: &name,
			Properties: &armpolicy.DefinitionProperties{
				DisplayName: &name,
				Version:     &version,
			},
		},
	}
}

func fakePolicyDefinitionless(name string) *PolicyDefinition {
	return &PolicyDefinition{
		Definition: armpolicy.Definition{
			Name: &name,
			Properties: &armpolicy.DefinitionProperties{
				DisplayName: &name,
			},
		},
	}
}

func TestVersionedPolicyCollection_Upsert_VersionedDefinitions(t *testing.T) {
	c1 := NewPolicyDefinitionVersions()
	c2 := NewPolicyDefinitionVersions()

	v1 := "1.0.0"
	v2 := "2.0.0"
	p1 := fakePolicyDefinitioned("foo", v1)
	p2 := fakePolicyDefinitioned("foo", v2)
	require.NoError(t, c1.Add(p1, false))
	require.NoError(t, c2.Add(p2, false))

	err := c1.Upsert(c2, false)
	assert.NoError(t, err)
	sv, errVer := semver.NewVersion(v2)
	require.NoError(t, errVer)
	got, ok := c1.versions[*sv]
	assert.True(t, ok)
	assert.Equal(t, v2, *got.GetVersion())
}

func TestVersionedPolicyCollection_Upsert_OverwriteVersioned(t *testing.T) {
	c1 := NewPolicyDefinitionVersions()
	c2 := NewPolicyDefinitionVersions()

	v := "1.0.0"
	p1 := fakePolicyDefinitioned("foo", v)
	p2 := fakePolicyDefinitioned("foo", v)
	require.NoError(t, c1.Add(p1, false))
	require.NoError(t, c2.Add(p2, false))

	err := c1.Upsert(c2, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	err2 := c1.Upsert(c2, true)
	require.NoError(t, err2)
	sv, errVer := semver.NewVersion(v)
	require.NoError(t, errVer)
	got, ok := c1.versions[*sv]
	assert.True(t, ok)
	assert.Equal(t, v, *got.GetVersion())
}

func TestVersionedPolicyCollection_Upsert_VersionlessDefinitions(t *testing.T) {
	c1 := NewPolicyDefinitionVersions()
	c2 := NewPolicyDefinitionVersions()

	p := fakePolicyDefinitionless("foo")
	require.NoError(t, c2.Add(p, false))

	err := c1.Upsert(c2, false)
	assert.NoError(t, err)
	assert.NotNil(t, c1.versionlessDefinition)
	assert.Equal(t, "foo", *c1.versionlessDefinition.GetName())
}

func TestVersionedPolicyCollection_Upsert_VersionlessConflict(t *testing.T) {
	c1 := NewPolicyDefinitionVersions()
	c2 := NewPolicyDefinitionVersions()

	p1 := fakePolicyDefinitionless("foo")
	p2 := fakePolicyDefinitionless("bar")
	require.NoError(t, c1.Add(p1, false))
	require.NoError(t, c2.Add(p2, false))

	err := c1.Upsert(c2, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot merge versionless definitions")

	err2 := c1.Upsert(c2, true)
	assert.NoError(t, err2)
	assert.Equal(t, "bar", *c1.versionlessDefinition.GetName())
}

func TestVersionedPolicyCollection_Upsert_VersionlessWithVersionedTarget(t *testing.T) {
	c1 := NewPolicyDefinitionVersions()
	c2 := NewPolicyDefinitionVersions()

	v := "1.0.0"
	p := fakePolicyDefinitioned("foo", v)
	require.NoError(t, c1.Add(p, false))
	require.NoError(t, c2.Add(fakePolicyDefinitionless("foo"), false))

	err := c1.Upsert(c2, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot merge versionless definitions when versioned definitions already exist")
}

func TestVersionedPolicyCollection_Upsert_VersionedWithVersionlessTarget(t *testing.T) {
	c1 := NewPolicyDefinitionVersions()
	c2 := NewPolicyDefinitionVersions()

	require.NoError(t, c1.Add(fakePolicyDefinitionless("foo"), false))
	v := "1.0.0"
	p := fakePolicyDefinitioned("foo", v)
	require.NoError(t, c2.Add(p, false))

	err := c1.Upsert(c2, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot merge versioned definitions when versionless definition already exists")
}

func TestVersionedPolicyCollection_Upsert_NilInput(t *testing.T) {
	c1 := NewPolicyDefinitionVersions()
	err := c1.Upsert(nil, false)
	assert.NoError(t, err)
}

func TestVersionedPolicyCollection_Upsert_EmptyInput(t *testing.T) {
	c1 := NewPolicyDefinitionVersions()
	c2 := NewPolicyDefinitionVersions()
	err := c1.Upsert(c2, false)
	assert.NoError(t, err)
}
