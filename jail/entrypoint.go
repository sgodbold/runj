package jail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"go.sbk.wtf/runj/oci"
	"go.sbk.wtf/runj/state"
)

const (
	execFifoFilename = "exec.fifo"
	execSkipFifo     = "-"
	consoleSocketEnv = "__RUNJ_CONSOLE_SOCKET"
	stdioFdCount     = 3
)

// SetupEntrypoint starts a runj-entrypoint process, which is used to start
// processes inside the jail.
//
// When used to start the jail's init process, runj-entrypoint will later be
// signalled through `runj start` to run the specified program in the jail. This
// indirection is necessary so that the STDIO for `runj create` or the supplied
// console socket is directed to that process.
//
// When used to start a secondary process inside the jail, the waiting step is
// skipped and runj-entrypoint will immediately proceed to create the process
// as soon as STDIO is configured.
//
// Note: this API is unstable; expect it to change.
// The init process's configuration (cwd, and in the future
// user/umask/rlimits/...) is not passed here: runj-entrypoint reads it back
// from the persisted config.json once it is inside the jail.  See
// docs/entrypoint-process-config.md.
func SetupEntrypoint(id string, init bool, argv []string, env []string, consoleSocketPath string) (*exec.Cmd, error) {
	path := execSkipFifo
	if init {
		var err error
		path, err = createExecFifo(id)
		if err != nil {
			return nil, err
		}
	}
	args := append([]string{id, path}, argv...)
	cmd := exec.Command("runj-entrypoint", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	// the caller of runj will handle receiving the console master
	if consoleSocketPath != "" {
		conn, err := net.Dial("unix", consoleSocketPath)
		if err != nil {
			return nil, err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			return nil, errors.New("casting to UnixConn failed")
		}
		consoleSocket, err := uc.File()
		if err != nil {
			return nil, err
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, consoleSocket)
		cmd.Env = append(cmd.Env,
			consoleSocketEnv+"="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		)
	}

	return cmd, cmd.Start()
}

// ExecEntrypoint execs a runj-entrypoint process in order to start a secondary
// process inside the jail.
//
// The process's configuration (cwd, and in the future user/umask/rlimits/...)
// is persisted to the state directory and read back by runj-entrypoint once it
// is inside the jail, rather than being passed on runj-entrypoint's argument or
// environment contract.  Because this function exec(2)s into runj-entrypoint,
// the pid is preserved, so runj-entrypoint can find the file with getpid(2).
// See docs/entrypoint-process-config.md for the rationale.
//
// Note: this API is unstable; expect it to change.
func ExecEntrypoint(id string, process *runtimespec.Process, consoleSocketPath string) error {
	env := process.Env
	// the caller of runj will handle receiving the console master
	if consoleSocketPath != "" {
		conn, err := net.Dial("unix", consoleSocketPath)
		if err != nil {
			return err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			return errors.New("casting to UnixConn failed")
		}
		consoleSocket, err := uc.File()
		if err != nil {
			return err
		}
		fd, err := unix.Dup(int(consoleSocket.Fd()))
		if err != nil {
			return err
		}
		env = append(env, consoleSocketEnv+"="+strconv.Itoa(fd))
	}
	path, err := exec.LookPath("runj-entrypoint")
	if err != nil {
		return err
	}
	// Persist the process configuration keyed by this pid, which is preserved
	// across the exec(2) below so runj-entrypoint can read it back.
	pid := os.Getpid()
	if err := oci.StoreProcess(id, pid, process); err != nil {
		return err
	}
	args := append([]string{"runj-entrypoint", id, execSkipFifo}, process.Args...)
	err = unix.Exec(path, args, env)
	// unix.Exec only returns on failure; clean up the file we just wrote since
	// no runj-entrypoint will consume it.
	oci.RemoveProcess(id, pid)
	return err
}

// CleanupEntrypoint sends a SIGTERM to the PID recorded in the state file.
// This function returns with no error even if the process is not running or
// cannot be signaled.
func CleanupEntrypoint(id string) error {
	s, err := state.Load(id)
	if err != nil {
		return err
	}
	if s.PID == 0 {
		return nil
	}
	e, _ := os.FindProcess(s.PID)
	e.Signal(syscall.SIGTERM)
	return nil
}

// inspired by runc

// createExecFifo creates a fifo for communication between runj and
// runj-entrypoint.
// See runc/libcontainer/container_linux.go for a similar example
func createExecFifo(id string) (string, error) {
	path := fifoPath(id)
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("fifo: exec fifo %s already exists", path)
	}
	// umask??
	if err := unix.Mkfifo(path, 0622); err != nil {
		return "", err
	}
	return path, nil
}

func fifoPath(id string) string {
	return filepath.Join(state.Dir(id), execFifoFilename)
}

// AwaitFifoOpen waits for a runj-entrypoint process to open the fifo passed to
// it.  The fifo is used to indicate when runj-entrypoint should start the
// process inside the jail.
func AwaitFifoOpen(ctx context.Context, id string) error {
	type openResult struct {
		file *os.File
		err  error
	}
	fifoOpened := make(chan openResult)
	go func() {
		f, err := fifoOpen(fifoPath(id))
		fifoOpened <- openResult{f, err}
		close(fifoOpened)
	}()
	select {
	case result := <-fifoOpened:
		if result.err != nil {
			return result.err
		}
		return handleFifoResult(result.file)
	case <-ctx.Done():
		return errors.New("fifo: timed out")
	}
}

func fifoOpen(path string) (*os.File, error) {
	flags := os.O_RDONLY
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("fifo: open exec fifo for reading: %w", err)
	}
	return f, nil
}

func handleFifoResult(f *os.File) error {
	defer f.Close()
	if err := readFromExecFifo(f); err != nil {
		return err
	}
	return os.Remove(f.Name())
}

func readFromExecFifo(execFifo io.Reader) error {
	data, err := io.ReadAll(execFifo)
	if err != nil {
		return err
	}
	if len(data) <= 0 {
		return errors.New("cannot start an already running container")
	}
	return nil
}

// end
