//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateDelete(t *testing.T) {
	dir, err := os.MkdirTemp("", "runj-integ-test-"+t.Name())
	require.NoError(t, err)
	defer func() {
		if !t.Failed() {
			os.RemoveAll(dir)
		} else {
			t.Log("preserving tempdir due to failure", dir)
		}
	}()

	tests := []runtimespec.Spec{
		// minimal
		{
			Process: &runtimespec.Process{},
		},
		// arguments
		{
			Process: &runtimespec.Process{
				Args: []string{"one", "two", "three"},
			},
		},
		// environment variables
		{
			Process: &runtimespec.Process{
				Env: []string{"one=two", "three=four", "five"},
			},
		},
		// hostname
		{
			Hostname: "foo.bar.example.com",
			Process:  &runtimespec.Process{},
		},
		// domainname
		{
			Domainname: "foo.bar.example.com",
			Process:    &runtimespec.Process{},
		},
		// ipv4
		{
			Process: &runtimespec.Process{},
			FreeBSD: &runtimespec.FreeBSD{
				Jail: &runtimespec.FreeBSDJail{
					Ip4:     runtimespec.FreeBSDShareNew,
					Ip4Addr: []string{"127.0.0.2"},
				},
			},
		},
		// ipv6
		{
			Process: &runtimespec.Process{},
			FreeBSD: &runtimespec.FreeBSD{
				Jail: &runtimespec.FreeBSDJail{
					Ip6:     runtimespec.FreeBSDShareNew,
					Ip6Addr: []string{"::1"},
				},
			},
		},
		// vnet
		{
			Process: &runtimespec.Process{},
			FreeBSD: &runtimespec.FreeBSD{
				Jail: &runtimespec.FreeBSDJail{
					Vnet: runtimespec.FreeBSDShareNew,
				},
			},
		},
	}

	for i, tc := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			bundleDir := filepath.Join(dir, strconv.Itoa(i))
			defer func() {
				if !t.Failed() {
					os.RemoveAll(bundleDir)
				} else {
					t.Log("preserving tempdir due to failure", bundleDir)
				}
			}()
			rootDir := filepath.Join(bundleDir, "root")
			err := os.MkdirAll(rootDir, 0755)
			require.NoError(t, err, "create bundle dir")
			t.Log("bundle", bundleDir)

			configJSON, err := json.Marshal(tc)
			require.NoError(t, err, "marshal config")
			err = os.WriteFile(filepath.Join(bundleDir, "config.json"), configJSON, 0644)
			require.NoError(t, err, "write config")

			id := "integ-test-create-delete-" + strconv.Itoa(i)
			var cmd *exec.Cmd
			switch i % 3 {
			case 0:
				cmd = exec.Command("runj", "create", id, bundleDir, "--pid-file", "jail.pid")
				t.Log("using argument form")
			case 1:
				cmd = exec.Command("runj", "create", id, "--bundle", bundleDir, "--pid-file", "jail.pid")
				t.Log("using --bundle form")
			case 2:
				cmd = exec.Command("runj", "create", id, "-b", bundleDir, "--pid-file", "jail.pid")
				t.Log("using -b form")
			default:
				t.Fatalf("Unhandled test variant; %d%%3 = %d", i, i%3)
			}
			cmd.Stdin = nil
			out, err := os.OpenFile(filepath.Join(bundleDir, "out"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			require.NoError(t, err, "out file")
			cmd.Stdout = out
			cmd.Stderr = out
			err = cmd.Run()
			assert.NoError(t, err, "runj create")
			err = out.Close()
			assert.NoError(t, err, "out file close")
			outBytes, err := os.ReadFile(filepath.Join(bundleDir, "out"))
			assert.NoError(t, err, "out file read")
			t.Log("runj create output:", string(outBytes))

			pidfile, err := os.ReadFile("jail.pid")
			assert.NoError(t, err)
			t.Logf("pid: %q", string(pidfile))

			cmd = exec.Command("runj", "delete", id)
			cmd.Stdin = nil
			outBytes, err = cmd.CombinedOutput()
			assert.NoError(t, err, "runj delete")
			t.Log("runj delete output:", string(outBytes))
		})
	}
}

func TestStateOCIVersion(t *testing.T) {
	// A version distinct from runj's own constant, to prove the bundle's
	// version is reported rather than runj's.
	const ociVersion = "1.1.0-test"

	dir, err := os.MkdirTemp("", "runj-integ-test-"+t.Name())
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "root"), 0755), "create root dir")

	spec := runtimespec.Spec{
		Version: ociVersion,
		Process: &runtimespec.Process{},
	}
	configJSON, err := json.Marshal(spec)
	require.NoError(t, err, "marshal config")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), configJSON, 0644), "write config")

	const id = "integ-test-ociversion"
	exec.Command("runj", "delete", id).Run() // best-effort: clear any leftover
	t.Cleanup(func() { exec.Command("runj", "delete", id).Run() })

	if out, err := exec.Command("runj", "create", id, dir).CombinedOutput(); err != nil {
		t.Fatalf("runj create: %v: %s", err, out)
	}

	out, err := exec.Command("runj", "state", id).Output()
	require.NoError(t, err, "runj state")
	var st struct {
		OCIVersion string `json:"ociVersion"`
	}
	require.NoError(t, json.Unmarshal(out, &st), "parse state output")
	assert.Equal(t, ociVersion, st.OCIVersion, "state should report the bundle's ociVersion")
}

func TestJailHello(t *testing.T) {
	spec := setupSimpleExitingJail(t)

	spec.Process = &runtimespec.Process{
		Args: []string{"/integ-inside", "-test.v", "-test.run", "TestHello"},
	}

	stdout, stderr, err := runExitingJail(t, "integ-test-hello", spec, 500*time.Millisecond)
	assert.NoError(t, err)
	t.Log("STDOUT:", string(stdout))
	t.Log("STDERR:", string(stderr))
}

func TestJailEnv(t *testing.T) {
	env := []string{"Hello=World", "FOO=bar"}

	spec := setupSimpleExitingJail(t)

	spec.Process = &runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestEnv"},
		Env:  env,
	}

	stdout, stderr, err := runExitingJail(t, "integ-test-env", spec, 500*time.Millisecond)
	assert.NoError(t, err)
	assertJailPass(t, stdout, stderr)
	lines := strings.Split(string(stdout), "\n")
	assert.ElementsMatch(t, env, lines[:len(lines)-2], "environment variables should match")
	if t.Failed() {
		t.Log("STDOUT:", string(stdout))
	}
}

func TestJailCwd(t *testing.T) {
	const workdir = "/workdir"

	spec := setupSimpleExitingJail(t)

	err := os.Mkdir(filepath.Join(spec.Root.Path, workdir), 0755)
	require.NoError(t, err, "create working directory")

	spec.Process = &runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestCwd"},
		Cwd:  workdir,
	}

	stdout, stderr, err := runExitingJail(t, "integ-test-cwd", spec, 500*time.Millisecond)
	assert.NoError(t, err)
	assertJailPass(t, stdout, stderr)
	lines := strings.Split(string(stdout), "\n")
	assert.Len(t, lines, 3, "should be exactly 3 lines of output")
	assert.Equal(t, workdir, lines[0], "working directory should match process.cwd")
	if t.Failed() {
		t.Log("STDOUT:", string(stdout))
	}
}

func TestJailUser(t *testing.T) {
	var umask uint32 = 0o027

	spec := setupSimpleExitingJail(t)
	spec.Process = &runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestUser"},
		User: runtimespec.User{
			UID:            1000,
			GID:            1000,
			Umask:          &umask,
			AdditionalGids: []uint32{2000, 3000},
		},
	}

	stdout, stderr, err := runExitingJail(t, "integ-test-user", spec, 500*time.Millisecond)
	assert.NoError(t, err)
	assertJailPass(t, stdout, stderr)
	out := string(stdout)
	assert.Contains(t, out, "uid=1000", "uid should match process.user.uid")
	assert.Contains(t, out, "gid=1000", "gid should match process.user.gid")
	assert.Contains(t, out, "umask=0027", "umask should match process.user.umask")
	assert.Contains(t, out, "2000", "groups should include additional gid 2000")
	assert.Contains(t, out, "3000", "groups should include additional gid 3000")
	if t.Failed() {
		t.Log("STDOUT:", out)
	}
}

func TestJailNullMount(t *testing.T) {
	spec := setupSimpleExitingJail(t)

	volume := t.TempDir()
	err := os.WriteFile(filepath.Join(volume, "hello.txt"), []byte("input file"), 0644)
	require.NoError(t, err, "input file")

	spec.Process = &runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestNullMount"},
	}
	spec.Mounts = []runtimespec.Mount{{
		Destination: "/volume",
		Type:        "nullfs",
		Source:      volume,
	}}
	stdout, stderr, err := runExitingJail(t, "integ-test-null", spec, 500*time.Millisecond)
	assert.NoError(t, err)
	assertJailPass(t, stdout, stderr)
	output, err := os.ReadFile(filepath.Join(volume, "world.txt"))
	assert.NoError(t, err, "failed to read world.txt")
	assert.Equal(t, "output file", string(output))
	if t.Failed() {
		t.Log("STDOUT:", string(stdout))
	}
}

func TestJailHostname(t *testing.T) {
	hostname := fmt.Sprintf("%s.example", t.Name())

	spec := setupSimpleExitingJail(t)

	spec.Hostname = hostname
	spec.Process = &runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestHostname"},
	}

	stdout, stderr, err := runExitingJail(t, "integ-test-hostname", spec, 500*time.Millisecond)
	assert.NoError(t, err)
	assertJailPass(t, stdout, stderr)
	lines := strings.Split(string(stdout), "\n")
	assert.Len(t, lines, 3, "should be exactly 3 lines of output")
	assert.Equal(t, hostname, lines[0], "hostname should match")
	if t.Failed() {
		t.Log("STDOUT:", string(stdout))
	}
}

func TestJailHostMode(t *testing.T) {
	// jls reports the host jailsys mode the kernel recorded for the jail.
	// A jail defaults to inherit, so a jail reporting new confirms the
	// host=new parameter reached the kernel.  A hostname read inside the
	// jail cannot tell the modes apart: without host.hostname every mode
	// reports the host's hostname.
	modes := []runtimespec.FreeBSDSharing{
		runtimespec.FreeBSDShareNew,
		runtimespec.FreeBSDShareInherit,
	}
	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			spec := runtimespec.Spec{
				Process: &runtimespec.Process{},
				FreeBSD: &runtimespec.FreeBSD{
					Jail: &runtimespec.FreeBSDJail{Host: mode},
				},
			}
			id := "integ-test-host-" + string(mode)
			if out, err := createJail(t, id, spec); err != nil {
				t.Fatalf("runj create: %v: %s", err, out)
			}

			out, err := exec.Command("jls", "-j", id, "host").CombinedOutput()
			require.NoError(t, err, "jls -j %s host: %s", id, out)
			assert.Equal(t, string(mode), strings.TrimSpace(string(out)), "jls should report the configured host mode")
		})
	}
}

func TestJailHostInheritHostnameConflict(t *testing.T) {
	// host: inherit shares the host's UTS information, but specifying a
	// hostname causes the kernel to give the jail its own UTS information
	// instead (i.e., host: new). Rather than allowing the kernel
	// silent-override behavior, runj explicitly rejects this case.
	spec := runtimespec.Spec{
		Hostname: "conflict.example",
		Process:  &runtimespec.Process{},
		FreeBSD: &runtimespec.FreeBSD{
			Jail: &runtimespec.FreeBSDJail{Host: runtimespec.FreeBSDShareInherit},
		},
	}
	out, err := createJail(t, "integ-test-host-inherit-hostname", spec)
	require.Error(t, err, "runj create should reject host: inherit with a hostname: %s", out)
	assert.Contains(t, string(out), "cannot set Hostname", "error should explain the conflict")
}

func TestJailHostInheritDomainnameConflict(t *testing.T) {
	// host: inherit shares the host's UTS information, but specifying a
	// domainname causes the kernel to give the jail its own UTS information
	// instead (i.e., host: new). Rather than allowing the kernel
	// silent-override behavior, runj explicitly rejects this case.
	spec := runtimespec.Spec{
		Domainname: "conflict.example",
		Process:    &runtimespec.Process{},
		FreeBSD: &runtimespec.FreeBSD{
			Jail: &runtimespec.FreeBSDJail{Host: runtimespec.FreeBSDShareInherit},
		},
	}
	out, err := createJail(t, "integ-test-host-inherit-domainname", spec)
	require.Error(t, err, "runj create should reject host: inherit with a domainname: %s", out)
	assert.Contains(t, string(out), "cannot set Domainname", "error should explain the conflict")
}

func TestJailDomainname(t *testing.T) {
	domainname := fmt.Sprintf("%s.example", t.Name())

	spec := setupSimpleExitingJail(t)

	spec.Domainname = domainname
	spec.Process = &runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestDomainname"},
	}

	stdout, stderr, err := runExitingJail(t, "integ-test-domainname", spec, 500*time.Millisecond)
	assert.NoError(t, err)
	assertJailPass(t, stdout, stderr)
	lines := strings.Split(string(stdout), "\n")
	assert.Len(t, lines, 3, "should be exactly 3 lines of output")
	assert.Equal(t, domainname, lines[0], "domainname should match")
	if t.Failed() {
		t.Log("STDOUT:", string(stdout))
	}
}

func TestJailExec(t *testing.T) {
	j := startSimpleRunningJail(t, "integ-test-exec")

	stdout, stderr, err := j.exec(t, runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestHello"},
	})
	assert.NoError(t, err)
	assert.Empty(t, stderr, "exec stderr should be empty")
	assert.Contains(t, string(stdout), "Hello println!", "exec output should contain greeting")
	lines := strings.Split(string(stdout), "\n")
	require.GreaterOrEqual(t, len(lines), 2, "stdout should have at least two lines")
	assert.Equal(t, "PASS", lines[len(lines)-2], "exec process should pass")
	if t.Failed() {
		t.Log("STDOUT:", string(stdout))
		t.Log("STDERR:", string(stderr))
	}
}

func TestJailExecCwd(t *testing.T) {
	const workdir = "/workdir"

	j := startSimpleRunningJail(t, "integ-test-exec-cwd")

	err := os.Mkdir(filepath.Join(j.root, workdir), 0755)
	require.NoError(t, err, "create working directory")

	stdout, stderr, err := j.exec(t, runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestCwd"},
		Cwd:  workdir,
	})
	assert.NoError(t, err)
	assert.Empty(t, stderr, "exec stderr should be empty")
	lines := strings.Split(string(stdout), "\n")
	require.GreaterOrEqual(t, len(lines), 2, "stdout should have at least two lines")
	assert.Equal(t, "PASS", lines[len(lines)-2], "exec process should pass")
	assert.Equal(t, workdir, lines[0], "working directory should match process.cwd")
	if t.Failed() {
		t.Log("STDOUT:", string(stdout))
		t.Log("STDERR:", string(stderr))
	}
}

// TestJailExecCwdRelativeRejected confirms runj rejects a non-absolute cwd,
// which the OCI spec requires to be absolute, before starting the process.
func TestJailExecCwdRelativeRejected(t *testing.T) {
	j := startSimpleRunningJail(t, "integ-test-exec-cwd-rel")

	_, stderr, err := j.exec(t, runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestCwd"},
		Cwd:  "workdir",
	})
	require.Error(t, err, "runj exec should reject a relative cwd")
	assert.Contains(t, string(stderr), "must be an absolute path", "error should explain the rejection")
}

// TestJailExecCwdNonexistent confirms runj fails the exec when the cwd does not
// exist inside the jail rather than silently ignoring it.
func TestJailExecCwdNonexistent(t *testing.T) {
	j := startSimpleRunningJail(t, "integ-test-exec-cwd-missing")

	_, _, err := j.exec(t, runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestCwd"},
		Cwd:  "/does-not-exist",
	})
	require.Error(t, err, "runj exec should fail when cwd does not exist")
}

func TestJailExecUser(t *testing.T) {
	var umask uint32 = 0o027

	j := startSimpleRunningJail(t, "integ-test-exec-user")

	stdout, stderr, err := j.exec(t, runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestUser"},
		User: runtimespec.User{
			UID:            1000,
			GID:            1000,
			Umask:          &umask,
			AdditionalGids: []uint32{2000, 3000},
		},
	})
	assert.NoError(t, err)
	assert.Empty(t, stderr, "exec stderr should be empty")
	out := string(stdout)
	assert.Contains(t, out, "uid=1000", "uid should match process.user.uid")
	assert.Contains(t, out, "gid=1000", "gid should match process.user.gid")
	assert.Contains(t, out, "umask=0027", "umask should match process.user.umask")
	assert.Contains(t, out, "2000", "groups should include additional gid 2000")
	assert.Contains(t, out, "3000", "groups should include additional gid 3000")
	if t.Failed() {
		t.Log("STDOUT:", out)
		t.Log("STDERR:", string(stderr))
	}
}

// TestJailExecUserCwdPermission confirms runj-entrypoint applies process.user
// before changing to process.cwd: the cwd is a directory only root may enter,
// so the chdir fails once the process has dropped to the unprivileged user.
func TestJailExecUserCwdPermission(t *testing.T) {
	const rootOnlyDir = "/rootonly"

	j := startSimpleRunningJail(t, "integ-test-exec-user-cwd")

	err := os.Mkdir(filepath.Join(j.root, rootOnlyDir), 0700)
	require.NoError(t, err, "create root-only working directory")

	_, stderr, err := j.exec(t, runtimespec.Process{
		Args: []string{"/integ-inside", "-test.run", "TestCwd"},
		Cwd:  rootOnlyDir,
		User: runtimespec.User{UID: 1000, GID: 1000},
	})
	require.Error(t, err, "runj exec should fail to enter a root-only cwd as the unprivileged user")
	assert.Contains(t, string(stderr), "permission denied", "chdir should fail with a permission error")
}
