package main

import (
	"flag"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/groob/go-simian/internal/facts"
	"github.com/groob/go-simian/simian"
)

func main() {
	var (
		flReport = flag.String("report", "preflight", "report type")
	)
	flag.Parse()
	_ = flReport

	sp, err := facts.SPHardwareDataType()
	if err != nil {
		log.Fatal(err)
	}
	uuid := sp["SPHardwareDataType"][0].PlatformUUID
	client, err := simian.NewClient(GetServerURL())
	if err != nil {
		log.Fatal(err)
	}
	cookie := fmt.Sprintf("Cookie: %s", client.Auth1Token())
	macUUID := fmt.Sprintf("X-munki-client-id: %s", strings.ToLower(uuid))
	headers := []string{macUUID, cookie}
	if err := setAdditionalHeaders(headers); err != nil {
		log.Fatal(err)
	}
}

// TODO write with cfprefs
func setAdditionalHeaders(headers []string) error {
	args := []string{"write", "/Library/Preferences/ManagedInstalls.plist", "AdditionalHttpHeaders", "-array"}
	args = append(args, headers...)
	_, err := exec.Command("/usr/bin/defaults", args...).CombinedOutput()
	return err
}
