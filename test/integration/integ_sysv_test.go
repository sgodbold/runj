//go:build integration
// +build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runSysVProbe runs the named inside probe in a simple jail configured with the
// given jail settings (nil for a default jail) and asserts the jail exits
// cleanly with PASS.
func runSysVProbe(t *testing.T, id, probe string, jail *runtimespec.FreeBSDJail) {
	t.Helper()
	spec := setupSimpleExitingJail(t)
	spec.Process = &runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", probe},
	}
	if jail != nil {
		spec.FreeBSD = &runtimespec.FreeBSD{Jail: jail}
	}
	stdout, stderr, err := runExitingJail(t, id, spec, 500*time.Millisecond)
	assert.NoError(t, err)
	assertJailPass(t, stdout, stderr)
	if t.Failed() {
		t.Log("STDOUT:", string(stdout))
	}
}

// TestJailSysVMsg creates a jail with sysvmsg=new and confirms a process inside
// it can create a SysV message queue, which a jail cannot do by default.
func TestJailSysVMsg(t *testing.T) {
	runSysVProbe(t, "integ-test-sysvmsg", "^TestSysVMsgQueue$",
		&runtimespec.FreeBSDJail{SysVMsg: runtimespec.FreeBSDShareNew})
}

// TestJailSysVMsgDenied creates a jail without sysvmsg (defaulting to disable)
// and confirms a process inside it cannot create a SysV message queue.  Paired
// with TestJailSysVMsg, it proves the sysvmsg parameter is what grants access.
// This and the sibling …Denied tests assume the host default
// security.jail.sysvipc_allowed=0; with it set to 1 a default jail permits IPC
// and they would fail.
func TestJailSysVMsgDenied(t *testing.T) {
	runSysVProbe(t, "integ-test-sysvmsg-denied", "^TestSysVMsgQueueDenied$", nil)
}

// TestJailSysVSem creates a jail with sysvsem=new and confirms a process inside
// it can create a SysV semaphore set, which a jail cannot do by default.
func TestJailSysVSem(t *testing.T) {
	runSysVProbe(t, "integ-test-sysvsem", "^TestSysVSemaphore$",
		&runtimespec.FreeBSDJail{SysVSem: runtimespec.FreeBSDShareNew})
}

// TestJailSysVSemDenied creates a jail without sysvsem (defaulting to disable)
// and confirms a process inside it cannot create a SysV semaphore set.  Paired
// with TestJailSysVSem, it proves the sysvsem parameter is what grants access.
func TestJailSysVSemDenied(t *testing.T) {
	runSysVProbe(t, "integ-test-sysvsem-denied", "^TestSysVSemaphoreDenied$", nil)
}

// TestJailSysVShm creates a jail with sysvshm=new and confirms a process inside
// it can create a SysV shared memory segment, which a jail cannot do by
// default.
func TestJailSysVShm(t *testing.T) {
	runSysVProbe(t, "integ-test-sysvshm", "^TestSysVShmem$",
		&runtimespec.FreeBSDJail{SysVShm: runtimespec.FreeBSDShareNew})
}

// TestJailSysVShmDenied creates a jail without sysvshm (defaulting to disable)
// and confirms a process inside it cannot create a SysV shared memory segment.
// Paired with TestJailSysVShm, it proves the sysvshm parameter is what grants
// access.
func TestJailSysVShmDenied(t *testing.T) {
	runSysVProbe(t, "integ-test-sysvshm-denied", "^TestSysVShmemDenied$", nil)
}

// TestJailSysVMode confirms each mode reaches the kernel by reading it back with
// jls.  The msgget/semget/shmget probes cannot tell new from inherit apart (both
// grant access), so jls is the only way to observe the exact recorded mode.
func TestJailSysVMode(t *testing.T) {
	params := []struct {
		name string
		set  func(*runtimespec.FreeBSDJail, runtimespec.FreeBSDSharing)
	}{
		{"sysvmsg", func(j *runtimespec.FreeBSDJail, m runtimespec.FreeBSDSharing) { j.SysVMsg = m }},
		{"sysvsem", func(j *runtimespec.FreeBSDJail, m runtimespec.FreeBSDSharing) { j.SysVSem = m }},
		{"sysvshm", func(j *runtimespec.FreeBSDJail, m runtimespec.FreeBSDSharing) { j.SysVShm = m }},
	}
	modes := []runtimespec.FreeBSDSharing{
		runtimespec.FreeBSDShareNew,
		runtimespec.FreeBSDShareInherit,
	}
	for _, p := range params {
		for _, mode := range modes {
			t.Run(p.name+"-"+string(mode), func(t *testing.T) {
				jail := &runtimespec.FreeBSDJail{}
				p.set(jail, mode)
				spec := runtimespec.Spec{
					Process: &runtimespec.Process{},
					FreeBSD: &runtimespec.FreeBSD{Jail: jail},
				}
				id := "integ-test-" + p.name + "-" + string(mode)
				if out, err := createJail(t, id, spec); err != nil {
					t.Fatalf("runj create: %v: %s", err, out)
				}
				out, err := exec.Command("jls", "-j", id, p.name).CombinedOutput()
				require.NoError(t, err, "jls -j %s %s: %s", id, p.name, out)
				assert.Equal(t, string(mode), strings.TrimSpace(string(out)), "jls should report the configured mode")
			})
		}
	}
}
