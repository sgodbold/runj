//go:build inside
// +build inside

package integration

import (
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// FreeBSD sys/ipc.h values, which golang.org/x/sys/unix does not export for
// freebsd.
const (
	ipcPrivate = 0
	ipcCreat   = 0o1000
	ipcRmid    = 0
)

func TestHello(t *testing.T) {
	fmt.Println("Hello println!")
	t.Log("Hello t.Log!")
}

// TestBlock keeps the init process alive so that a running jail can be exec'd
// into.  The harness kills the jail when the test is done.
func TestBlock(t *testing.T) {
	time.Sleep(time.Hour)
}

func TestEnv(t *testing.T) {
	for _, env := range os.Environ() {
		fmt.Println(env)
	}
}

func TestNullMount(t *testing.T) {
	stat, err := os.Stat("/volume/hello.txt")
	assert.NoError(t, err, "cannot stat hello.txt")
	assert.Equal(t, fs.FileMode(0), stat.Mode()&fs.ModeType, "unexpected file mode")
	input, err := os.ReadFile("/volume/hello.txt")
	assert.NoError(t, err, "cannot read hello.txt")
	assert.Equal(t, "input file", string(input), "unexpected file contents")
	err = os.WriteFile("/volume/world.txt", []byte("output file"), 0644)
	assert.NoError(t, err, "cannot write world.txt")
}

func TestHostname(t *testing.T) {
	hostname, err := os.Hostname()
	assert.NoError(t, err, "failed to retrieve hostname")
	fmt.Println(hostname)
}

// TestIP6Visible asserts that the IPv6 address the jail was configured with
// (TEST_IP6ADDR) is visible on one of the jail's interfaces.  If the jail's
// ip6.addr parameter never reached the kernel, the jail's network stack would
// not expose the address and this fails.
func TestIP6Visible(t *testing.T) {
	want := net.ParseIP(os.Getenv("TEST_IP6ADDR"))
	require.NotNil(t, want, "TEST_IP6ADDR must be a valid IP address")

	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err, "failed to list interface addresses")

	seen := make([]string, 0, len(addrs))
	found := false
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		seen = append(seen, ipnet.IP.String())
		// To4 returns nil for a genuine IPv6 address.
		if ipnet.IP.To4() == nil && ipnet.IP.Equal(want) {
			found = true
		}
	}
	assert.True(t, found, "expected IPv6 address %s visible in jail; saw %v", want, seen)
}

// TestEnforceStatfsCount prints the number of filesystems visible to the jail
// via getfsstat(2).  enforce_statfs restricts this count.
func TestEnforceStatfsCount(t *testing.T) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	assert.NoError(t, err, "getfsstat")
	fmt.Println(n)
}

func TestDomainname(t *testing.T) {
	domainname, err := unix.Sysctl("kern.domainname")
	assert.NoError(t, err, "failed to retrieve domainname")
	fmt.Println(domainname)
}

// TestSysVMsgQueue creates a SysV message queue via msgget(2).  A jail can do
// this only when sysvmsg is enabled (new or inherit); it is disabled by
// default.
func TestSysVMsgQueue(t *testing.T) {
	id, _, errno := unix.Syscall(unix.SYS_MSGGET, uintptr(ipcPrivate), uintptr(ipcCreat|0o600), 0)
	require.Zero(t, errno, "msgget should succeed when sysvmsg is enabled: %v", errno)
	unix.Syscall(unix.SYS_MSGCTL, id, uintptr(ipcRmid), 0)
}

// TestSysVMsgQueueDenied confirms msgget(2) fails when sysvmsg is disabled,
// which is a jail's default.  Paired with TestSysVMsgQueue, it establishes that
// the sysvmsg parameter is what grants access rather than the host permitting
// SysV IPC unconditionally.
func TestSysVMsgQueueDenied(t *testing.T) {
	id, _, errno := unix.Syscall(unix.SYS_MSGGET, uintptr(ipcPrivate), uintptr(ipcCreat|0o600), 0)
	if errno == 0 {
		unix.Syscall(unix.SYS_MSGCTL, id, uintptr(ipcRmid), 0)
	}
	assert.NotZero(t, errno, "msgget should fail when sysvmsg is disabled")
}

// TestSysVSemaphore creates a SysV semaphore set via semget(2).  A jail can do
// this only when sysvsem is enabled (new or inherit); it is disabled by
// default.
func TestSysVSemaphore(t *testing.T) {
	id, _, errno := unix.Syscall(unix.SYS_SEMGET, uintptr(ipcPrivate), 1, uintptr(ipcCreat|0o600))
	require.Zero(t, errno, "semget should succeed when sysvsem is enabled: %v", errno)
	unix.Syscall6(unix.SYS___SEMCTL, id, 0, uintptr(ipcRmid), 0, 0, 0)
}

// TestSysVSemaphoreDenied confirms semget(2) fails when sysvsem is disabled,
// which is a jail's default.  Paired with TestSysVSemaphore, it establishes
// that the sysvsem parameter is what grants access rather than the host
// permitting SysV IPC unconditionally.
func TestSysVSemaphoreDenied(t *testing.T) {
	id, _, errno := unix.Syscall(unix.SYS_SEMGET, uintptr(ipcPrivate), 1, uintptr(ipcCreat|0o600))
	if errno == 0 {
		unix.Syscall6(unix.SYS___SEMCTL, id, 0, uintptr(ipcRmid), 0, 0, 0)
	}
	assert.NotZero(t, errno, "semget should fail when sysvsem is disabled")
}

// TestSysVShmem creates a SysV shared memory segment via shmget(2).  A jail can
// do this only when sysvshm is enabled (new or inherit); it is disabled by
// default.
func TestSysVShmem(t *testing.T) {
	id, _, errno := unix.Syscall(unix.SYS_SHMGET, uintptr(ipcPrivate), uintptr(os.Getpagesize()), uintptr(ipcCreat|0o600))
	require.Zero(t, errno, "shmget should succeed when sysvshm is enabled: %v", errno)
	unix.Syscall(unix.SYS_SHMCTL, id, uintptr(ipcRmid), 0)
}

// TestSysVShmemDenied confirms shmget(2) fails when sysvshm is disabled, which
// is a jail's default.  Paired with TestSysVShmem, it establishes that the
// sysvshm parameter is what grants access rather than the host permitting SysV
// IPC unconditionally.
func TestSysVShmemDenied(t *testing.T) {
	id, _, errno := unix.Syscall(unix.SYS_SHMGET, uintptr(ipcPrivate), uintptr(os.Getpagesize()), uintptr(ipcCreat|0o600))
	if errno == 0 {
		unix.Syscall(unix.SYS_SHMCTL, id, uintptr(ipcRmid), 0)
	}
	assert.NotZero(t, errno, "shmget should fail when sysvshm is disabled")
}

func TestCwd(t *testing.T) {
	wd, err := os.Getwd()
	assert.NoError(t, err, "failed to retrieve working directory")
	fmt.Println(wd)
}

// TestConsoleSize reports the window size of the process's controlling
// terminal.  When the jail is created with process.terminal true and a
// process.consoleSize, runj-entrypoint resizes the console pty before wiring its
// slave to this process's stdio, so the size read here reflects the configured
// consoleSize.
func TestConsoleSize(t *testing.T) {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	assert.NoError(t, err, "failed to get window size")
	if err == nil {
		fmt.Printf("winsize rows=%d cols=%d\n", ws.Row, ws.Col)
	}
}

func TestRlimit(t *testing.T) {
	var rl unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_CORE, &rl)
	assert.NoError(t, err, "failed to retrieve RLIMIT_CORE")
	fmt.Printf("core soft=%d hard=%d\n", rl.Cur, rl.Max)
}

func TestUser(t *testing.T) {
	fmt.Printf("uid=%d\n", os.Getuid())
	fmt.Printf("gid=%d\n", os.Getgid())
	groups, err := os.Getgroups()
	assert.NoError(t, err, "failed to retrieve groups")
	fmt.Printf("groups=%v\n", groups)
	old := syscall.Umask(0)
	syscall.Umask(old)
	fmt.Printf("umask=%04o\n", old)
}

func TestLocalhostHTTPHello(t *testing.T) {
	port := os.Getenv("TEST_PORT")
	requestURL := fmt.Sprintf("http://127.0.0.1:%s/hello", port)
	resp, err := http.Get(requestURL)
	assert.NoError(t, err, "failed to get from %q", requestURL)
	if err == nil {
		defer resp.Body.Close()
	}
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err, "failed to read body")
	fmt.Println(string(body))
}

func TestVnetConfigAndPing(t *testing.T) {
	var (
		iface   = os.Getenv("TEST_INTERFACE")
		ip      = os.Getenv("TEST_IP")
		mask    = os.Getenv("TEST_MASK")
		gateway = os.Getenv("TEST_GATEWAY")
		pingIP  = os.Getenv("TEST_PING_IP")
	)
	out, err := exec.Command("/sbin/ifconfig", iface, "inet", ip+"/"+mask).CombinedOutput()
	t.Logf("ifconfig %s inet %s/%s: %s", iface, ip, mask, string(out))
	assert.NoError(t, err)

	out, err = exec.Command("/sbin/route", "-4", "add", "default", gateway).CombinedOutput()
	t.Logf("route -4 add default %s: %s", ip, string(out))
	assert.NoError(t, err)

	out, err = exec.Command("/sbin/ping", "-c2", pingIP).CombinedOutput()
	t.Logf("ping -c2 %s: %s", pingIP, string(out))
	assert.NoError(t, err)
}
