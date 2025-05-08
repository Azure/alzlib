package assets

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyVersionConstraintToSemVerConstraint(t *testing.T) {
	tests := []struct {
		name        string // The name of the test case
		constraint  string // The version constraint to test
		version     string // The version to test against the constraint
		match       bool   // Whether we expect a match
		expectError bool   // Whether we expect an error
		errorSubstr string // A substring of the error message we expect
	}{
		{
			name:        "valid constraint with wildcard patch",
			constraint:  "1.2.*",
			version:     "1.2.3",
			match:       true,
			expectError: false,
		},
		{
			name:        "invalid constraint - wildcard major",
			constraint:  "*.2.*",
			version:     "1.2.3",
			match:       false,
			expectError: true,
			errorSubstr: "wildcard in major version",
		},
		{
			name:        "invalid constraint - no wildcard patch",
			constraint:  "1.2.3",
			version:     "1.2.3",
			match:       false,
			expectError: true,
			errorSubstr: "wildcard in patch version",
		},
		{
			name:        "invalid constraint - no wildcard patch with prerelease",
			constraint:  "1.2.3",
			version:     "1.2.3-alpha",
			match:       false,
			expectError: true,
			errorSubstr: "wildcard in patch version",
		},
		{
			name:        "invalid constraint - not enough components",
			constraint:  "1.2",
			version:     "",
			match:       false,
			expectError: true,
			errorSubstr: "three dot-separated components",
		},
		{
			name:        "invalid constraint - too many components",
			constraint:  "1.2.3.4",
			version:     "",
			match:       false,
			expectError: true,
			errorSubstr: "three dot-separated components",
		},
		{
			name:        "invalid constraint - empty string",
			constraint:  "",
			version:     "",
			match:       false,
			expectError: true,
			errorSubstr: "three dot-separated components",
		},
		{
			name:        "prerelease",
			constraint:  "1.2.*-alpha",
			version:     "1.2.3-alpha",
			match:       true,
			expectError: false,
		},
		{
			name:        "prerelease no match version without prerelease",
			constraint:  "1.2.*",
			version:     "1.2.3-alpha",
			match:       false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := policyVersionConstraintToSemVerConstraint(tt.constraint)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorSubstr != "" {
					assert.Contains(t, err.Error(), tt.errorSubstr)
				}
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				require.NotNil(t, c)
				// Check that the constraint parses as expected
				v, _ := semver.NewVersion(tt.version)
				ok, _ := c.Validate(v)
				assert.Equal(t, tt.match, ok)
			}
		})
	}
}

func TestSemverCheckPrereleaseStrict(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		constraint     string
		expectedResult bool
	}{
		{
			name:           "matching prerelease",
			version:        "1.2.3-alpha",
			constraint:     "1.2.*-alpha",
			expectedResult: true,
		},
		{
			name:           "non-matching prerelease",
			version:        "1.2.3-beta",
			constraint:     "1.2.*-alpha",
			expectedResult: false,
		},
		{
			name:           "no prerelease in version, constraint has prerelease",
			version:        "1.2.3",
			constraint:     "1.2.*-alpha",
			expectedResult: false,
		},
		{
			name:           "prerelease in version, constraint has no prerelease",
			version:        "1.2.3-alpha",
			constraint:     "1.2.*",
			expectedResult: false,
		},
		{
			name:           "no prerelease in both version and constraint",
			version:        "1.2.3",
			constraint:     "1.2.*",
			expectedResult: true,
		},
		{
			name:           "prerelease with build metadata",
			version:        "1.2.3-alpha+001",
			constraint:     "1.2.*-alpha",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := semver.NewVersion(tt.version)
			require.NoError(t, err)
			c, err := semver.NewConstraint(tt.constraint)
			require.NoError(t, err)
			result := semverCheckPrereleaseStrict(v, c)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
