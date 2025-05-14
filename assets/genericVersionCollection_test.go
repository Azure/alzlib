package assets

import (
	"maps"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionedPolicyCollection_Add_VersionlessFirst(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "Test Policy"
	policy := fakePolicyDefinitionVersionless(name)
	require.NoError(t, pdvs.Add(policy))
	assert.Equal(t, policy, pdvs.versionlessDefinition)
}

func TestVersionedPolicyCollection_Add_VersionedFirst(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "Test Policy"
	version := "1.0.0"
	policy := fakePolicyDefinitionVersioned(name, version)
	require.NoError(t, pdvs.Add(policy))
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
	version := "1.0.0"
	policy1 := fakePolicyDefinitionVersioned("Policy1", version)
	policy2 := fakePolicyDefinitionVersioned("Policy2", version)
	require.NoError(t, pdvs.Add(policy1))
	require.ErrorContains(t, pdvs.Add(policy2), "version 1.0.0 for Policy2 already exists")
}

func TestVersionedPolicyCollection_Add_MixVersionedAndVersionless(t *testing.T) {
	version := "1.0.0"
	versioned := fakePolicyDefinitionVersioned("Policy1", version)
	versionless := fakePolicyDefinitionVersionless("Policy2")

	t.Run("versioned first", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()
		require.NoError(t, pdvs.Add(versioned))
		require.ErrorContains(t, pdvs.Add(versionless), "versioned definitions already exist")
	})

	t.Run("versionless first", func(t *testing.T) {
		pdvs := NewPolicyDefinitionVersions()
		require.NoError(t, pdvs.Add(versionless))
		require.ErrorContains(t, pdvs.Add(versioned), "versionless definition(s) already exists")
	})
}

func TestVersionedPolicyCollection_Add_InvalidVersionString(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "Test Policy"
	version := "not-a-semver"
	policy := fakePolicyDefinitionVersioned(name, version)
	require.ErrorContains(t, pdvs.Add(policy), "invalid version string")
}

func TestVersionedPolicyCollection_Add_NilPolicyOrProperties(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	require.Error(t, pdvs.Add(nil))
}

func TestVersionedPolicyCollection_Add_DifferentName(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	policy1 := fakePolicyDefinitionVersioned("Policy1", "1.0.0")
	policy2 := fakePolicyDefinitionVersioned("Policy2", "1.0.1")

	require.NoError(t, pdvs.Add(policy1))
	require.ErrorContains(t, pdvs.Add(policy2), "cannot add with different name than existing version.")
}

func TestVersionedPolicyCollection_GetVersion_Versionless(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "PolicyVersionless"
	versionless := fakePolicyDefinitionVersionless(name)
	require.NoError(t, pdvs.Add(versionless))

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
		assert.ErrorContains(t, err, "no version found for constraint")
		assert.Nil(t, got)
	})
}

func TestVersionedPolicyCollection_GetVersion_Versioned(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "PolicyVersioned"
	v1 := "1.0.0"
	v2 := "2.0.0"
	policy1 := fakePolicyDefinitionVersioned(name, v1)
	policy2 := fakePolicyDefinitionVersioned(name, v2)
	require.NoError(t, pdvs.Add(policy1))
	require.NoError(t, pdvs.Add(policy2))

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
		constr := "1.0.0"
		got, err := pdvs.GetVersion(&constr)
		require.ErrorContains(t, err, "version constraint should have wildcard in patch version")
		assert.Nil(t, got)
	})
}

func TestVersionedPolicyCollection_GetVersion_InvalidConstraint(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "PolicyVersioned"
	v1 := "1.0.0"
	policy := fakePolicyDefinitionVersioned(name, v1)
	require.NoError(t, pdvs.Add(policy))

	constr := "not-a-semver"
	got, err := pdvs.GetVersion(&constr)
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestVersionedPolicyCollection_GetVersion_WildcardConstraint(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "PolicyVersioned"
	v1 := "1.0.0"
	policy := fakePolicyDefinitionVersioned(name, v1)
	require.NoError(t, pdvs.Add(policy))

	constr := "1.*.0"
	got, err := pdvs.GetVersion(&constr)
	assert.Error(t, err)
	assert.Nil(t, got)
}

func fakePolicyDefinitionVersioned(name string, version string) *PolicyDefinitionVersion {
	return &PolicyDefinitionVersion{
		DefinitionVersion: armpolicy.DefinitionVersion{
			Name: &name,
			Properties: &armpolicy.DefinitionVersionProperties{
				DisplayName: &name,
				Version:     &version,
			},
		},
	}
}

func fakePolicyDefinitionVersionless(name string) *PolicyDefinitionVersion {
	return &PolicyDefinitionVersion{
		DefinitionVersion: armpolicy.DefinitionVersion{
			Name: &name,
			Properties: &armpolicy.DefinitionVersionProperties{
				DisplayName: &name,
			},
		},
	}
}
