package facts

import (
	"bytes"
	"os/exec"

	"github.com/groob/plist"
)

type spData struct {
	DetailType string           `plist:"_dataType"`
	Items      []SPDataTypeItem `plist:"_items"`
}

type SPDataTypeItem struct {
	PlatformUUID string `plist:"platform_UUID"`
	SerialNumber string `plist:"serial_number"`
	Hostname     string `plist:"local_host_name"`
	Username     string `plist:"user_name"`
}

func SystemProfiler() (map[string][]SPDataTypeItem, error) {
	data, err := getMacData()
	if err != nil {
		return nil, err
	}
	var sp []spData
	err = plist.Unmarshal(data, &sp)
	if err != nil {
		return nil, err
	}
	dict := make(map[string][]SPDataTypeItem, len(sp))
	for _, dt := range sp {
		dict[dt.DetailType] = dt.Items
	}
	return dict, nil
}

func getMacData() ([]byte, error) {
	out, err := exec.Command("/usr/sbin/system_profiler", "SPHardwareDataType", "SPSoftwareDataType", "-xml").CombinedOutput()
	if err != nil {
		return nil, err
	}
	data := bytes.Replace(out, []byte(`<integer>-2</integer>`), []byte(`<string>-2</string>`), -1)
	return data, nil
}
