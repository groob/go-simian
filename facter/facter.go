package facter

import (
	"strings"

	"github.com/groob/go-simian/internal/cfpref"
	"github.com/groob/go-simian/internal/facts"
	"github.com/pkg/errors"
)

const managedInstallsPlist = "/Library/Preferences/ManagedInstalls.plist"

type Facter struct {
	systemProfilerData map[string][]facts.SPDataTypeItem
	serverURL          string
}

func NewFacter() (*Facter, error) {
	f := &Facter{
		systemProfilerData: make(map[string][]facts.SPDataTypeItem),
	}
	sp, err := facts.SystemProfiler()
	if err != nil {
		return nil, errors.Wrap(err, "getting system_profiler data types")
	}
	f.systemProfilerData = sp

	repoURL := cfpref.CopyAppValue("SoftwareRepoURL", managedInstallsPlist)
	f.serverURL = repoURL.String()

	return f, nil
}

func (f *Facter) ClientVersion() string {
	return "3.3.3 2.2.2"
}

func (f *Facter) ServerURL() string {
	return f.serverURL
}

func (f *Facter) HardwareUUID() string {
	uuid := f.systemProfilerData["SPHardwareDataType"][0].PlatformUUID
	return strings.ToLower(uuid)
}

func (f *Facter) ConsoleUser() string {
	username := f.systemProfilerData["SPSoftwareDataType"][0].Username
	username = strings.SplitN(username, " ", 2)[0]
	return username
}

func (f *Facter) PrimatryUser() string {
	// TODO use /usr/bin/last
	return f.ConsoleUser()
}

func (f *Facter) Uptime() string {
}
