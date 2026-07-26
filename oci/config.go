package oci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"go.sbk.wtf/runj/internal/util"
	runjspec "go.sbk.wtf/runj/runtimespec"
	"go.sbk.wtf/runj/state"
)

const (
	// ConfigFileName is the name of the config file
	ConfigFileName = "config.json"

	// RunjExtensionFileName is the name of an additional file, specifying only
	// the experimental FreeBSD section, which can be merged into the regular
	// bundle config.  This allows for software which generates a config file
	// unaware of FreeBSD and runj to be augmented by an additional program
	// that specifies additional settings.
	RunjExtensionFileName = "runj.ext.json"
)

// StoreConfig copies the config file provided in the input bundle to the state
// directory for the container.  The file must be copied to comply with this
// requirement from the OCI runtime specification:
// Any changes made to the config.json file after this operation will not have
// an effect on the container.
func StoreConfig(id, bundlePath string) error {
	err := util.CopyFile(filepath.Join(bundlePath, ConfigFileName), filepath.Join(state.Dir(id), ConfigFileName), 0600)
	if err != nil {
		return err
	}
	extFilename := filepath.Join(bundlePath, RunjExtensionFileName)
	if _, err = os.Stat(extFilename); err == nil {
		err = util.CopyFile(extFilename, filepath.Join(state.Dir(id), RunjExtensionFileName), 0600)
		if err != nil {
			return err
		}
	}
	return nil
}

// LoadConfig loads the config file stored in the state directory
func LoadConfig(id string) (*runtimespec.Spec, error) {
	data, err := os.ReadFile(filepath.Join(state.Dir(id), ConfigFileName))
	if err != nil {
		return nil, err
	}
	config := &runtimespec.Spec{}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(filepath.Join(state.Dir(id), RunjExtensionFileName)); err == nil {
		extData, err := os.ReadFile(filepath.Join(state.Dir(id), RunjExtensionFileName))
		if err != nil {
			return nil, err
		}
		freebsd := &runjspec.FreeBSD{}
		err = json.Unmarshal(extData, freebsd)
		if err != nil {
			return nil, err
		}
		merge(config, freebsd)
	}
	return config, nil
}

// processFileName returns the name of the file used to persist the process
// configuration for a secondary (exec'd) process, keyed by the pid of the
// runj-entrypoint that will run it.  See StoreProcess for why this is keyed by
// pid and docs/entrypoint-process-config.md for the overall design.
func processFileName(pid int) string {
	return fmt.Sprintf("process.%d.json", pid)
}

// StoreProcess persists the configuration for a secondary process (one started
// by `runj exec` rather than the jail's init process) to the container's state
// directory.
//
// Unlike the init process, whose configuration is part of the persisted
// config.json, a secondary process is transient and per-invocation, so its
// configuration cannot be read back from config.json.  runj-entrypoint runs
// inside the jail and needs the process configuration (cwd, and in the future
// user/umask/rlimits/...) after it has chroot'd, so the configuration must be
// handed to it out-of-band.  Rather than widen runj-entrypoint's argument or
// environment contract (which would break across version skew; see the design
// doc), runj writes the configuration here and runj-entrypoint reads it back
// with LoadProcess.
//
// The file is keyed by pid: `runj exec` exec(2)s into runj-entrypoint, which
// preserves the pid, so runj-entrypoint can locate its own file with getpid(2)
// without anything extra being passed on the wire.  Concurrent execs use
// distinct pids and therefore distinct files.
func StoreProcess(id string, pid int, process *runtimespec.Process) error {
	data, err := json.Marshal(process)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(state.Dir(id), processFileName(pid)), data, 0600)
}

// LoadProcess loads the configuration for a secondary process previously
// persisted by StoreProcess.
func LoadProcess(id string, pid int) (*runtimespec.Process, error) {
	data, err := os.ReadFile(filepath.Join(state.Dir(id), processFileName(pid)))
	if err != nil {
		return nil, err
	}
	process := &runtimespec.Process{}
	if err := json.Unmarshal(data, process); err != nil {
		return nil, err
	}
	return process, nil
}

// RemoveProcess removes the persisted configuration for a secondary process.
// Any files not removed here (e.g. if runj-entrypoint dies before consuming
// its file) are cleaned up when the container's state directory is removed on
// delete.
func RemoveProcess(id string, pid int) error {
	return os.Remove(filepath.Join(state.Dir(id), processFileName(pid)))
}

// ValidateProcess checks the process fields runj applies from inside the jail.
// The OCI runtime spec requires process.cwd to be an absolute path; runj treats
// an empty cwd as the jail root but rejects a relative one, which would resolve
// against an unspecified directory.
func ValidateProcess(process *runtimespec.Process) error {
	if process == nil {
		return nil
	}
	if process.Cwd != "" && !filepath.IsAbs(process.Cwd) {
		return fmt.Errorf("process.cwd must be an absolute path, got %q", process.Cwd)
	}
	return nil
}

// merge processes an existing spec and additional FreeBSD section to merge them
// together.  Fields specified in the original spec are preserved except in the
// case where they are overwritten.  Slices the FreeBSD section are appended to
// slices specified in the original spec.
func merge(spec *runtimespec.Spec, freebsd *runjspec.FreeBSD) {
	if spec == nil || freebsd == nil {
		return
	}
	if spec.FreeBSD == nil {
		spec.FreeBSD = &runtimespec.FreeBSD{}
	}
	if spec.FreeBSD.Jail == nil {
		spec.FreeBSD.Jail = &runtimespec.FreeBSDJail{}
	}
	if freebsd.Network != nil {
		if freebsd.Network.IPv4 != nil {
			if freebsd.Network.IPv4.Mode != "" {
				spec.FreeBSD.Jail.Ip4 = runtimespec.FreeBSDSharing(freebsd.Network.IPv4.Mode)
			}
			if len(freebsd.Network.IPv4.Addr) > 0 {
				spec.FreeBSD.Jail.Ip4Addr = append(spec.FreeBSD.Jail.Ip4Addr, freebsd.Network.IPv4.Addr...)
			}
		}
		if freebsd.Network.VNet != nil {
			if freebsd.Network.VNet.Mode != "" {
				spec.FreeBSD.Jail.Vnet = runtimespec.FreeBSDSharing(freebsd.Network.VNet.Mode)
			}
			if len(freebsd.Network.VNet.Interfaces) > 0 {
				spec.FreeBSD.Jail.VnetInterfaces = append(spec.FreeBSD.Jail.VnetInterfaces, freebsd.Network.VNet.Interfaces...)
			}
		}
	}
}
