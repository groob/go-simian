package simian

import "testing"

func TestLoadConfig(t *testing.T) {
	path := "testdata/settings.cfg"
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if have, want := cfg.Domain, "appspot.com"; have != want {
		t.Errorf("have %s, want %s", have, want)
	}

	if have, want := cfg.Subdomain, "example"; have != want {
		t.Errorf("have %s, want %s", have, want)
	}

	if have, want := cfg.AppleSUS, true; have != want {
		t.Errorf("have %v, want %v", have, want)
	}
}
