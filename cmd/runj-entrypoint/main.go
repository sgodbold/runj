/*
runj-entrypoint is a small helper program for starting processes inside OCI
jails.  This program is used for ensuring that the jail process's STDIO is
hooked up to the right STDIO streams.

When used for the jail's init process, the STDIO streams should match that of
`runj create`.  In this scenario, this program is started when `runj create` is
invoked, but blocks until `runj start` is invoked.

Unfortunately, this program works through indirection that is not obvious.  When
`runj create` is run, it creates a fifo (see mkfifo(2)) and then starts this
program, passing the jail ID, the path to the fifo, and the program that should
be invoked as arguments.  This program then opens the fifo for writing, which
should block to wait for the right time to actually exec into the target
program.  `runj start` will open the fifo for reading, which unblocks this
program and the jail process can start.

The above procedure is skipped when secondary processes are started, since there
is no create/start split involved for these processes and the STDIO of `runj
extension exec` is used directly.

This program exec(2)s to into the final target program.  The sequence of
exec(2)` preserves the PID so that it can be the target of a future invocation
of `runj kill`.

Process attributes that must be applied from inside the jail (currently the
working directory; in the future the user, umask, rlimits, and so on) are not
passed on this program's command line or environment.  Instead this program
reads them back from the container's state directory: from the persisted
config.json for the jail's init process, or from a per-pid file written by
`runj exec` for a secondary process.  See docs/entrypoint-process-config.md for
the rationale.
*/
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"go.sbk.wtf/runj/jail"
	"go.sbk.wtf/runj/oci"

	"github.com/containerd/console"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func main() {
	exit, err := _main()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(exit)
}

var errUsage = errors.New("usage: runj-entrypoint JAIL-ID FIFO-PATH PROGRAM [ARGS...]")

const (
	consoleSocketEnv = "__RUNJ_CONSOLE_SOCKET"

	// skipExecFifo signals that the exec fifo sync procedure should be skipped
	skipExecFifo = "-"
)

func _main() (int, error) {
	if len(os.Args) < 4 {
		return 1, errUsage
	}
	jid := os.Args[1]
	fifoPath := os.Args[2]
	command := os.Args[3]
	argv := os.Args[4:]

	// Load the process configuration up front: the console size is applied to
	// the terminal set up below, and the user and working directory are applied
	// after attaching to the jail.  The configuration lives in the container's
	// state directory on the host filesystem, which is no longer reachable once
	// Attach chroots us into the jail root.  See
	// docs/entrypoint-process-config.md for why this is read here rather than
	// passed as an argument or environment variable.
	process, err := loadProcess(jid, fifoPath == skipExecFifo)
	if err != nil {
		return 2, err
	}

	var consoleSize *runtimespec.Box
	if process != nil {
		consoleSize = process.ConsoleSize
	}
	if err := setupConsole(consoleSize); err != nil {
		return 3, err
	}

	if fifoPath != skipExecFifo {
		// Block until `runj start` is invoked
		fifofd, err := unix.Open(fifoPath, unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return 4, fmt.Errorf("failed to open fifo: %w", err)
		}
		if _, err := unix.Write(fifofd, []byte("0")); err != nil {
			return 5, fmt.Errorf("failed to write to fifo: %w", err)
		}
	}

	j, err := jail.FromName(jid)
	if err != nil {
		return 6, err
	}

	// attach places us inside the jail and implicitly does a chroot
	err = j.Attach()
	if err != nil {
		return 7, err
	}

	// drop to the configured user before changing directory and exec'ing, so
	// that the working directory and program are resolved with the container
	// process's credentials.
	if err := applyUser(process); err != nil {
		return 8, err
	}

	// change to the process's working directory, resolved relative to the
	// jail's root by the chroot that Attach performed.  An empty or absent cwd
	// defaults to the jail root.
	cwd := "/"
	if process != nil && process.Cwd != "" {
		cwd = process.Cwd
	}
	if err := os.Chdir(cwd); err != nil {
		return 9, fmt.Errorf("failed to chdir to %q: %w", cwd, err)
	}

	// unix.Exec requires the full path to the supplied command
	cmdpath, err := exec.LookPath(command)
	if err != nil {
		return 10, err
	}
	// call unix.Exec (which is execve(2)) to replace this process with the command
	if err := unix.Exec(cmdpath, append([]string{command}, argv...), unix.Environ()); err != nil {
		return 11, fmt.Errorf("failed to exec: %w", err)
	}
	return 0, nil
}

// applyUser applies process.user (umask, additionalGids, gid, uid) to the
// current process before it execs the container program.  The group list and
// gid are set before the uid, because dropping the uid removes the privilege to
// set them.  An omitted user deserializes to the zero-valued User and is
// applied the same as an explicit uid 0 / gid 0: the process runs as root with
// no supplementary groups other than gid 0.
func applyUser(process *runtimespec.Process) error {
	if process == nil {
		return nil
	}
	user := process.User
	if user.Umask != nil {
		unix.Umask(int(*user.Umask))
	}
	// On FreeBSD the first entry of the group list is the effective gid, and
	// setgroups sets the whole list, so the gid leads the list and the
	// additionalGids follow it as supplementary groups.
	gids := make([]int, 0, len(user.AdditionalGids)+1)
	gids = append(gids, int(user.GID))
	for _, gid := range user.AdditionalGids {
		gids = append(gids, int(gid))
	}
	if err := unix.Setgroups(gids); err != nil {
		return fmt.Errorf("setgroups %v: %w", gids, err)
	}
	if err := unix.Setgid(int(user.GID)); err != nil {
		return fmt.Errorf("setgid %d: %w", user.GID, err)
	}
	if err := unix.Setuid(int(user.UID)); err != nil {
		return fmt.Errorf("setuid %d: %w", user.UID, err)
	}
	return nil
}

// loadProcess returns the configuration for the process this entrypoint will
// run.  For the jail's init process the configuration is read from the
// persisted config.json; for a secondary process started by `runj exec` it is
// read from a per-pid file that runj wrote before exec(2)ing into us (keyed by
// our pid, which the exec preserved).  Reading the configuration here, rather
// than receiving it through runj-entrypoint's argument or environment contract,
// keeps that contract stable across runj/runj-entrypoint version skew and
// scales to the other process.* fields without new wiring.  See
// docs/entrypoint-process-config.md.
func loadProcess(jid string, secondary bool) (*runtimespec.Process, error) {
	if secondary {
		pid := os.Getpid()
		process, err := oci.LoadProcess(jid, pid)
		if err != nil {
			return nil, err
		}
		// We have consumed the file; remove it while the host filesystem is
		// still reachable (before Attach chroots us).
		oci.RemoveProcess(jid, pid)
		return process, nil
	}
	config, err := oci.LoadConfig(jid)
	if err != nil {
		return nil, err
	}
	return config.Process, nil
}

// setupConsole allocates a pty for the container process when a console socket
// was provided (i.e. process.terminal is true) and sends its master end back
// over that socket.  consoleSize, when set, gives the pty's window size; it is
// ignored when there is no console socket, matching the spec requirement to
// ignore consoleSize when terminal is false.
func setupConsole(consoleSize *runtimespec.Box) error {
	socketFdArg := os.Getenv(consoleSocketEnv)
	if socketFdArg == "" {
		return nil
	}
	os.Unsetenv(consoleSocketEnv)
	socketFd, err := strconv.Atoi(socketFdArg)
	if err != nil {
		return fmt.Errorf("console: bad socket fd: %w", err)
	}
	socket := os.NewFile(uintptr(socketFd), "console-socket")
	// TODO clear env variable
	defer socket.Close()

	pty, slavePath, err := console.NewPty()
	if err != nil {
		return err
	}
	defer pty.Close()

	// Resize before sending the master and wiring the slave to the process's
	// stdio, so both ends carry the configured size before the process starts.
	if consoleSize != nil {
		if err := pty.Resize(console.WinSize{
			Height: uint16(consoleSize.Height),
			Width:  uint16(consoleSize.Width),
		}); err != nil {
			return fmt.Errorf("console: resize: %w", err)
		}
	}

	if err := SendFd(socket, pty.Name(), pty.Fd()); err != nil {
		return err
	}
	return dupStdio(slavePath)
}

// dupStdio opens the slavePath for the console and dups the fds to the current
// processes stdio, fd 0,1,2.
func dupStdio(slavePath string) error {
	fd, err := unix.Open(slavePath, unix.O_RDWR, 0)
	if err != nil {
		return &os.PathError{
			Op:   "open",
			Path: slavePath,
			Err:  err,
		}
	}

	if _, err := syscall.Setsid(); err != nil {
		return err
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCSCTTY, uintptr(0)); err != 0 {
		return err
	}
	for _, i := range []int{0, 1, 2} {
		if err := unix.Dup2(fd, i); err != nil {
			return err
		}
	}
	return nil
}
