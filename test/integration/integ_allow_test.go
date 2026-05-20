//go:build integration
// +build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJailAllowParameters confirms the FreeBSD jail allow settings in the OCI
// spec reach the kernel. jls -n renders enabled boolean parameters as their
// names and disabled parameters in their "no" form.
func TestJailAllowParameters(t *testing.T) {
	spec := runtimespec.Spec{
		Process: &runtimespec.Process{},
		FreeBSD: &runtimespec.FreeBSD{
			Jail: &runtimespec.FreeBSDJail{
				Allow: &runtimespec.FreeBSDJailAllow{
					SetHostname:   true,
					RawSockets:    true,
					Chflags:       false,
					Mount:         []string{"nullfs", "tmpfs"},
					Quotas:        false,
					SocketAf:      true,
					Mlock:         false,
					ReservedPorts: true,
					Suser:         false,
				},
			},
		},
	}

	const id = "integ-test-allow"
	if out, err := createJail(t, id, spec); err != nil {
		t.Fatalf("runj create: %v: %s", err, out)
	}

	params := []struct {
		name string
		want string
	}{
		{"allow.set_hostname", "allow.set_hostname"},
		{"allow.raw_sockets", "allow.raw_sockets"},
		{"allow.chflags", "allow.nochflags"},
		{"allow.mount.nullfs", "allow.mount.nullfs"},
		{"allow.mount.tmpfs", "allow.mount.tmpfs"},
		{"allow.quotas", "allow.noquotas"},
		{"allow.socket_af", "allow.socket_af"},
		{"allow.mlock", "allow.nomlock"},
		{"allow.reserved_ports", "allow.reserved_ports"},
		{"allow.suser", "allow.nosuser"},
	}
	for _, p := range params {
		t.Run(p.name, func(t *testing.T) {
			out, err := exec.Command("jls", "-n", "-j", id, p.name).CombinedOutput()
			require.NoError(t, err, "jls -n -j %s %s: %s", id, p.name, out)
			assert.Equal(t, p.want, strings.TrimSpace(string(out)), "jls should report the configured allow parameter")
		})
	}
}
