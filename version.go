package scribe

import "runtime/debug"

// BuildVersion and BuildCommit may be set with -ldflags -X.
var BuildVersion string
var BuildCommit string

// VersionInfo describes the embedded module, with unknown fields left empty.
type VersionInfo struct {
	Module   string
	Version  string
	Commit   string
	Modified bool
}

// Version reports module metadata without output or process-global flags.
func Version() VersionInfo {
	v := VersionInfo{Module: "github.com/SiriusScan/scribe", Version: BuildVersion, Commit: BuildCommit}
	if info, ok := debug.ReadBuildInfo(); ok {
		modules := append([]*debug.Module{&info.Main}, info.Deps...)
		for _, m := range modules {
			if m.Path == v.Module && v.Version == "" {
				v.Version = m.Version
			}
		}
		// VCS metadata describes this module only when it is the main module.
		if info.Main.Path == v.Module {
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if v.Commit == "" {
						v.Commit = s.Value
					}
				case "vcs.modified":
					v.Modified = s.Value == "true"
				}
			}
		}
	}
	return v
}
