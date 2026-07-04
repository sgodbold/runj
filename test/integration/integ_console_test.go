//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestJailConsoleSize verifies that process.consoleSize sets the window size of
// the container's console pty.  It checks the size from both ends of the pty:
//   - the master, which runj-entrypoint resizes and sends over the console
//     socket during `runj create`;
//   - the slave, by running an in-jail program that reads TIOCGWINSZ on its
//     controlling terminal and prints the size, which the test reads back over
//     the master after `runj start`.
//
// The values are deliberately not the 24x80 vt default so that a pty left
// unresized would not coincidentally pass.
func TestJailConsoleSize(t *testing.T) {
	const (
		id     = "integ-test-console-size"
		height = 40
		width  = 100
	)

	spec := setupSimpleExitingJail(t)
	spec.Process = &runtimespec.Process{
		Args:        []string{"/integ-inside", "-test.run", "TestConsoleSize"},
		Terminal:    true,
		ConsoleSize: &runtimespec.Box{Height: height, Width: width},
	}

	bundle, err := os.MkdirTemp("", "runj-integ-test-console")
	require.NoError(t, err, "create bundle dir")
	t.Cleanup(func() { os.RemoveAll(bundle) })
	configJSON, err := json.Marshal(spec)
	require.NoError(t, err, "marshal config")
	require.NoError(t, os.WriteFile(filepath.Join(bundle, "config.json"), configJSON, 0644), "write config")

	sockDir, err := os.MkdirTemp("", "runj-cs")
	require.NoError(t, err, "create socket dir")
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	listener, err := net.Listen("unix", filepath.Join(sockDir, "console.sock"))
	require.NoError(t, err, "listen on console socket")
	t.Cleanup(func() { listener.Close() })

	// Receive the console master in the background: runj-entrypoint connects and
	// sends it while `runj create` sets the console up, before the in-jail
	// process runs.  Read the master's window size, then drain the master until
	// the in-jail process has printed its own view of the size and exited
	// (closing the slave, which surfaces as a read error).
	type result struct {
		ws     *unix.Winsize
		output string
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		defer conn.Close()
		master, err := recvFd(conn.(*net.UnixConn))
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		defer master.Close()
		ws, err := unix.IoctlGetWinsize(int(master.Fd()), unix.TIOCGWINSZ)
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		var out strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		resultCh <- result{ws: ws, output: out.String()}
	}()

	exec.Command("runj", "delete", id).Run() // best-effort: clear any leftover
	t.Cleanup(func() { exec.Command("runj", "delete", id).Run() })

	create := exec.Command("runj", "create", id, bundle, "--console-socket", filepath.Join(sockDir, "console.sock"))
	create.Stdin = nil
	if out, err := create.CombinedOutput(); err != nil {
		t.Fatalf("runj create: %v: %s", err, out)
	}

	start := exec.Command("runj", "start", id)
	start.Stdin = nil
	if out, err := start.CombinedOutput(); err != nil {
		t.Fatalf("runj start: %v: %s", err, out)
	}

	select {
	case res := <-resultCh:
		require.NoError(t, res.err, "receive console master")
		assert.Equal(t, uint16(height), res.ws.Row, "console master height should match consoleSize.height")
		assert.Equal(t, uint16(width), res.ws.Col, "console master width should match consoleSize.width")
		want := fmt.Sprintf("winsize rows=%d cols=%d", height, width)
		assert.Contains(t, res.output, want, "in-jail process should observe the configured window size on its controlling terminal")
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for console master")
	}
}

// recvFd receives a single file descriptor sent over an AF_UNIX socket with
// SCM_RIGHTS, the way runj-entrypoint sends the console master.
func recvFd(conn *net.UnixConn) (*os.File, error) {
	name := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(name, oob)
	if err != nil {
		return nil, err
	}
	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	if len(scms) != 1 {
		return nil, fmt.Errorf("expected 1 control message, got %d", len(scms))
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil {
		return nil, err
	}
	if len(fds) != 1 {
		return nil, fmt.Errorf("expected 1 fd, got %d", len(fds))
	}
	return os.NewFile(uintptr(fds[0]), string(name[:n])), nil
}
