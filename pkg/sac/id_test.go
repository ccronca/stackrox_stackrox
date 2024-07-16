//go:build test_all

package sac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetIDForResource(t *testing.T) {
	cases := []struct {
		name     string
		expected ResourceID
		fail     bool
	}{
		{
			name: "valid global-scoped id",
			expected: ResourceID{
				suffix: "c",
			},
			fail: false,
		},
		{
			name: "valid global-scoped id: with all parts",
			expected: ResourceID{
				clusterID:   "a",
				namespaceID: "b",
				suffix:      "c",
			},
			fail: false,
		},
		{
			name: "valid cluster-scoped id",
			expected: ResourceID{
				clusterID: "a",
				suffix:    "c",
			},
			fail: false,
		},
		{
			name: "valid namespace-scoped id",
			expected: ResourceID{
				clusterID:   "a",
				namespaceID: "b",
				suffix:      "c",
			},
			fail: false,
		},
		{
			name:     "invalid id",
			expected: ResourceID{},
			fail:     true,
		},
		{
			name: "invalid namespace-scoped id: no cluster ID",
			expected: ResourceID{
				namespaceID: "b",
			},
			fail: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, err := ParseResourceID(c.expected.String())
			if c.fail {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expected, actual)
			}
		})
	}
}
