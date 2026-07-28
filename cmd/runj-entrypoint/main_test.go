package main

import (
	"math"
	"testing"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestApplyRlimitsNil confirms a process without rlimits (or no process at all)
// is a no-op rather than an error.
func TestApplyRlimitsNil(t *testing.T) {
	assert.NoError(t, applyRlimits(nil))
	assert.NoError(t, applyRlimits(&runtimespec.Process{}))
}

// TestApplyRlimitsUnknownType confirms an rlimit type with no FreeBSD
// equivalent is rejected.
func TestApplyRlimitsUnknownType(t *testing.T) {
	err := applyRlimits(&runtimespec.Process{
		Rlimits: []runtimespec.POSIXRlimit{
			{Type: "RLIMIT_RTPRIO", Soft: 1, Hard: 1},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RLIMIT_RTPRIO")
}

// TestApplyRlimitsRoundTrip confirms applyRlimits reaches setrlimit(2) with the
// configured value.  It lowers only the soft RLIMIT_CORE limit and keeps the
// hard limit, which is permitted without privilege, then reads it back.
func TestApplyRlimitsRoundTrip(t *testing.T) {
	var orig unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_CORE, &orig))
	t.Cleanup(func() {
		_ = unix.Setrlimit(unix.RLIMIT_CORE, &orig)
	})

	err := applyRlimits(&runtimespec.Process{
		Rlimits: []runtimespec.POSIXRlimit{
			{Type: "RLIMIT_CORE", Soft: 0, Hard: uint64(orig.Max)},
		},
	})
	require.NoError(t, err)

	var got unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_CORE, &got))
	assert.Equal(t, int64(0), got.Cur, "soft RLIMIT_CORE should match applied value")
}

// TestApplyRlimitsInfinity confirms FreeBSD stores a limit too large for the
// signed rlim_t as unlimited.
func TestApplyRlimitsInfinity(t *testing.T) {
	var orig unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_CORE, &orig))
	if orig.Max != unix.RLIM_INFINITY {
		t.Skipf("hard RLIMIT_CORE is %d; raising the soft limit to unlimited needs privilege", orig.Max)
	}
	t.Cleanup(func() {
		_ = unix.Setrlimit(unix.RLIMIT_CORE, &orig)
	})

	err := applyRlimits(&runtimespec.Process{
		Rlimits: []runtimespec.POSIXRlimit{
			{Type: "RLIMIT_CORE", Soft: math.MaxUint64, Hard: uint64(orig.Max)},
		},
	})
	require.NoError(t, err)

	var got unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_CORE, &got))
	assert.Equal(t, int64(unix.RLIM_INFINITY), got.Cur, "soft RLIMIT_CORE should be unlimited")
}
