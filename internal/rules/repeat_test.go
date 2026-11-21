package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRepeatCap(t *testing.T) {
	ok := "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: owner, repeat: 10}]\nmatch: a.ok\n"
	_, err := LoadFile(writeRule(t, ok))
	require.NoError(t, err)
	bad := "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: owner, repeat: 11}]\nmatch: a.ok\n"
	_, err = LoadFile(writeRule(t, bad))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repeat")
	neg := "id: AD-X-1\nname: t\nseverity: high\nsteps: [{name: a, as: owner, use: owner, repeat: -1}]\nmatch: a.ok\n"
	_, err = LoadFile(writeRule(t, neg))
	require.Error(t, err)
}
