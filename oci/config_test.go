package oci

import (
	"os"
	"testing"

	"github.com/go-faker/faker/v4"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"gotest.tools/v3/assert"

	runjspec "go.sbk.wtf/runj/runtimespec"
	"go.sbk.wtf/runj/state"
)

func TestMergeEmpty(t *testing.T) {
	spec := &runtimespec.Spec{}
	freebsd := &runjspec.FreeBSD{}
	err := faker.FakeData(freebsd)
	assert.NilError(t, err)

	merge(spec, freebsd)
	assert.Equal(t, string(spec.FreeBSD.Jail.Vnet), string(freebsd.Network.VNet.Mode))
	assert.DeepEqual(t, spec.FreeBSD.Jail.VnetInterfaces, freebsd.Network.VNet.Interfaces)
	assert.Equal(t, string(spec.FreeBSD.Jail.Ip4), string(freebsd.Network.IPv4.Mode))
	assert.DeepEqual(t, spec.FreeBSD.Jail.Ip4Addr, freebsd.Network.IPv4.Addr)
}

// TestMergeNilArguments verifies that merge tolerates nil inputs without
// panicking and without creating spec state.
func TestMergeNilArguments(t *testing.T) {
	// nil freebsd: spec must be left untouched.
	spec := &runtimespec.Spec{}
	merge(spec, nil)
	assert.Assert(t, spec.FreeBSD == nil)

	// nil spec: must not panic.
	merge(nil, &runjspec.FreeBSD{})
}

// TestMergeNilNetwork verifies that a FreeBSD section with no network still
// establishes the FreeBSD.Jail struct but sets no networking fields.
func TestMergeNilNetwork(t *testing.T) {
	spec := &runtimespec.Spec{}
	merge(spec, &runjspec.FreeBSD{})
	assert.Assert(t, spec.FreeBSD != nil)
	assert.Assert(t, spec.FreeBSD.Jail != nil)
	assert.Equal(t, string(spec.FreeBSD.Jail.Ip4), "")
	assert.Equal(t, string(spec.FreeBSD.Jail.Vnet), "")
}

func TestMergeIPv4Only(t *testing.T) {
	spec := &runtimespec.Spec{}
	merge(spec, &runjspec.FreeBSD{
		Network: &runjspec.FreeBSDNetwork{
			IPv4: &runjspec.FreeBSDIPv4{
				Mode: runjspec.FreeBSDIPv4ModeNew,
				Addr: []string{"127.0.0.2"},
			},
		},
	})
	assert.Equal(t, string(spec.FreeBSD.Jail.Ip4), "new")
	assert.DeepEqual(t, spec.FreeBSD.Jail.Ip4Addr, []string{"127.0.0.2"})
	// VNet was not specified and must remain unset.
	assert.Equal(t, string(spec.FreeBSD.Jail.Vnet), "")
	assert.Assert(t, spec.FreeBSD.Jail.VnetInterfaces == nil)
}

func TestMergeVNetOnly(t *testing.T) {
	spec := &runtimespec.Spec{}
	merge(spec, &runjspec.FreeBSD{
		Network: &runjspec.FreeBSDNetwork{
			VNet: &runjspec.FreeBSDVNet{
				Mode:       runjspec.FreeBSDVNetModeNew,
				Interfaces: []string{"epair0b"},
			},
		},
	})
	assert.Equal(t, string(spec.FreeBSD.Jail.Vnet), "new")
	assert.DeepEqual(t, spec.FreeBSD.Jail.VnetInterfaces, []string{"epair0b"})
	assert.Equal(t, string(spec.FreeBSD.Jail.Ip4), "")
	assert.Assert(t, spec.FreeBSD.Jail.Ip4Addr == nil)
}

// TestMergeAppendsToExisting verifies that address and interface lists from the
// FreeBSD section are appended to values already present in the spec.
func TestMergeAppendsToExisting(t *testing.T) {
	spec := &runtimespec.Spec{
		FreeBSD: &runtimespec.FreeBSD{
			Jail: &runtimespec.FreeBSDJail{
				Ip4Addr:        []string{"127.0.0.1"},
				VnetInterfaces: []string{"epair0b"},
			},
		},
	}
	merge(spec, &runjspec.FreeBSD{
		Network: &runjspec.FreeBSDNetwork{
			IPv4: &runjspec.FreeBSDIPv4{Addr: []string{"10.2.2.2"}},
			VNet: &runjspec.FreeBSDVNet{Interfaces: []string{"epair1b"}},
		},
	})
	assert.DeepEqual(t, spec.FreeBSD.Jail.Ip4Addr, []string{"127.0.0.1", "10.2.2.2"})
	assert.DeepEqual(t, spec.FreeBSD.Jail.VnetInterfaces, []string{"epair0b", "epair1b"})
}

// TestMergeEmptyModePreservesExisting verifies that an empty mode in the FreeBSD
// section does not overwrite a mode already set in the spec.
func TestMergeEmptyModePreservesExisting(t *testing.T) {
	spec := &runtimespec.Spec{
		FreeBSD: &runtimespec.FreeBSD{
			Jail: &runtimespec.FreeBSDJail{Ip4: "inherit"},
		},
	}
	merge(spec, &runjspec.FreeBSD{
		Network: &runjspec.FreeBSDNetwork{
			IPv4: &runjspec.FreeBSDIPv4{Addr: []string{"10.2.2.2"}},
		},
	})
	assert.Equal(t, string(spec.FreeBSD.Jail.Ip4), "inherit")
	assert.DeepEqual(t, spec.FreeBSD.Jail.Ip4Addr, []string{"10.2.2.2"})
}

func TestValidateProcess(t *testing.T) {
	tests := []struct {
		name    string
		process *runtimespec.Process
		wantErr bool
	}{
		{"nil", nil, false},
		{"empty cwd", &runtimespec.Process{}, false},
		{"absolute cwd", &runtimespec.Process{Cwd: "/workdir"}, false},
		{"relative cwd", &runtimespec.Process{Cwd: "workdir"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProcess(tc.process)
			if tc.wantErr {
				assert.ErrorContains(t, err, "must be an absolute path")
			} else {
				assert.NilError(t, err)
			}
		})
	}
}

func TestProcessFileName(t *testing.T) {
	assert.Equal(t, "process.1234.json", processFileName(1234))
}

func TestStoreLoadRemoveProcess(t *testing.T) {
	defer state.SetDir(t.TempDir())()
	const id = "test-process"
	assert.NilError(t, os.MkdirAll(state.Dir(id), 0755))

	const pid = 4321
	want := &runtimespec.Process{
		Cwd:  "/workdir",
		Args: []string{"/bin/sh", "-c", "true"},
		Env:  []string{"FOO=bar"},
	}
	assert.NilError(t, StoreProcess(id, pid, want))

	got, err := LoadProcess(id, pid)
	assert.NilError(t, err)
	assert.DeepEqual(t, want, got)

	assert.NilError(t, RemoveProcess(id, pid))
	_, err = LoadProcess(id, pid)
	assert.Assert(t, err != nil, "LoadProcess should fail after RemoveProcess")
}
