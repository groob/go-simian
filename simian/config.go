package simian

import (
	"github.com/pkg/errors"
	ini "gopkg.in/ini.v1"
)

// Config holds the Simian Client configuration
// located at /etc/simian/settings.cfg
type Config struct {
	Subdomain      string `ini:"subdomain"`
	Domain         string `ini:"domain"`
	RequiredIssuer string `ini:"required_issuer"`
	RootCAChainPEM string `ini:"root_ca_cert_chain_pem"`
	ClientSSLPath  string `ini:"client_ssl_path"`
	AuthDomain     string `ini:"auth_domain"`
	AppleSUS       bool   `ini:"applesus"`
	ConfigTrack    string `ini:"configtrack"`
	SimianTrack    string `ini:"simiantrack"`
	Certname       string `ini:"certname"`
	Hostname       string `ini:"hostname"`
	Site           string `ini:"site"`
}

func loadConfig(path string) (*Config, error) {
	cfg, err := ini.Load(path)
	if err != nil {
		return nil, errors.Wrap(err, "loading settings")
	}
	var settings Config
	if err := cfg.Section("settings").MapTo(&settings); err != nil {
		return nil, errors.Wrap(err, "map settings section to struct")
	}
	return &settings, err
}
