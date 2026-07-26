//go:build integration
// +build integration

package integration

import (
	"testing"
	"time"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
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
