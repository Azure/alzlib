package assets

import (
	"maps"
	"testing"

	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicySetDefinitionVersions_Add_VersionlessFirst(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "Test Policy"
	policy := fakePolicyDefinitionVersionless(name)
	require.NoError(t, pdvs.Add(policy))
	assert.Equal(t, policy, pdvs.versionlessDefinition)
}

func TestPolicySetDefinitionVersions_Add_VersionedFirst(t *testing.T) {
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

func TestPolicySetDefinitionVersions_Add_DuplicateSemVer(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	version := "1.0.0"
	policy1 := fakePolicyDefinitionVersioned("Policy1", version)
	policy2 := fakePolicyDefinitionVersioned("Policy2", version)
	require.NoError(t, pdvs.Add(policy1))
	require.ErrorContains(t, pdvs.Add(policy2), "version 1.0.0 for policy Policy2 already exists")
}

func TestPolicySetDefinitionVersions_Add_MixVersionedAndVersionless(t *testing.T) {
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
		require.ErrorContains(t, pdvs.Add(versioned), "versionless definition already exists")
	})
}

func TestPolicySetDefinitionVersions_Add_InvalidVersionString(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	name := "Test Policy"
	version := "not-a-semver"
	policy := fakePolicyDefinitionVersioned(name, version)
	require.ErrorContains(t, pdvs.Add(policy), "invalid version string")
}

func TestPolicySetDefinitionVersions_Add_NilPolicyOrProperties(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	require.Error(t, pdvs.Add(nil))

	policy := &PolicyDefinitionVersion{}
	require.Error(t, pdvs.Add(policy))
}

func TestPolicySetDefinitionVersions_Add_DifferentName(t *testing.T) {
	pdvs := NewPolicyDefinitionVersions()
	policy1 := fakePolicyDefinitionVersioned("Policy1", "1.0.0")
	policy2 := fakePolicyDefinitionVersioned("Policy2", "1.0.1")

	require.NoError(t, pdvs.Add(policy1))
	require.ErrorContains(t, pdvs.Add(policy2), "cannot add policy Policy2 with nil name or different name than existing version Policy1")
}

func TestPolicySetDefinitionVersions_GetVersion_Versionless(t *testing.T) {
	pdvs := NewPolicySetDefinitionVersions()
	name := "PolicyVersionless"
	versionless := fakePolicySetDefinitionVersionless(name)
	require.NoError(t, pdvs.Add(versionless))

	t.Run("nil version constraint", func(t *testing.T) {
		got, err := pdvs.GetVersion(nil)
		require.NoError(t, err)
		assert.Equal(t, versionless, got)
	})

	t.Run("empty version constraint", func(t *testing.T) {
		empty := ""
		got, err := pdvs.GetVersion(&empty)
		require.NoError(t, err)
		assert.Equal(t, versionless, got)
	})

	t.Run("non-empty version constraint returns nil", func(t *testing.T) {
		ver := "1.0.*"
		got, err := pdvs.GetVersion(&ver)
		assert.NoError(t, err)
		assert.Nil(t, got)
	})
}

func TestPolicySetDefinitionVersions_GetVersion_Versioned(t *testing.T) {
	pdvs := NewPolicySetDefinitionVersions()
	name := "PolicyVersioned"
	v1 := "1.0.0"
	v2 := "2.0.0"
	policy1 := fakePolicySetDefinitionVersioned(name, v1)
	policy2 := fakePolicySetDefinitionVersioned(name, v2)
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
		got, err := pdvs.GetVersion(&empty)
		require.NoError(t, err)
		assert.Equal(t, policy2, got)
	})

	t.Run("no match for constraint", func(t *testing.T) {
		constr := "3.0.*"
		got, err := pdvs.GetVersion(&constr)
		require.NoError(t, err)
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

func TestPolicySetDefinitionVersions_GetVersion_InvalidConstraint(t *testing.T) {
	pdvs := NewPolicySetDefinitionVersions()
	name := "PolicyVersioned"
	v1 := "1.0.0"
	policy := fakePolicySetDefinitionVersioned(name, v1)
	require.NoError(t, pdvs.Add(policy))

	constr := "not-a-semver"
	got, err := pdvs.GetVersion(&constr)
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestPolicySetDefinitionVersions_GetVersion_WildcardConstraint(t *testing.T) {
	pdvs := NewPolicySetDefinitionVersions()
	name := "PolicyVersioned"
	v1 := "1.0.0"
	policy := fakePolicySetDefinitionVersioned(name, v1)
	require.NoError(t, pdvs.Add(policy))

	constr := "1.*.0"
	got, err := pdvs.GetVersion(&constr)
	assert.Error(t, err)
	assert.Nil(t, got)
}

func fakePolicySetDefinitionVersioned(name string, version string) *PolicySetDefinitionVersion {
	return &PolicySetDefinitionVersion{
		SetDefinitionVersion: armpolicy.SetDefinitionVersion{
			Properties: &armpolicy.SetDefinitionVersionProperties{
				DisplayName: &name,
				Version:     &version,
			},
		},
	}
}

func fakePolicySetDefinitionVersionless(name string) *PolicySetDefinitionVersion {
	return &PolicySetDefinitionVersion{
		SetDefinitionVersion: armpolicy.SetDefinitionVersion{
			Properties: &armpolicy.SetDefinitionVersionProperties{
				DisplayName: &name,
			},
		},
	}
}
