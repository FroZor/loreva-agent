//go:build linux

package metrics

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeSysfs(t *testing.T, root string, files map[string]string) {
	t.Helper()

	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCollectRAIDReportsDegradedArrayAndRecovery(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOST_SYS", root)
	writeSysfs(t, root, map[string]string{
		"block/md0/md/level":          "raid1",
		"block/md0/md/array_state":    "clean",
		"block/md0/md/raid_disks":     "2",
		"block/md0/md/degraded":       "1",
		"block/md0/md/sync_action":    "recover",
		"block/md0/md/sync_completed": "250 / 1000",
		"block/md0/md/dev-sda1/state": "in_sync",
		"block/md0/md/dev-sdb1/state": "faulty,write_error",
		"block/sda/queue/rotational":  "0",
	})

	arrays := collectRAID()
	if len(arrays) != 1 {
		t.Fatalf("arrays = %+v", arrays)
	}
	array := arrays[0]
	if array.DeviceID != "storage:md0" || array.Level != "raid1" || array.Disks != 2 || array.Degraded != 1 {
		t.Fatalf("array = %+v", array)
	}
	if !slices.Equal(array.FailedMembers, []string{"sdb1"}) || array.SyncAction != "recover" || array.SyncPercent == nil || *array.SyncPercent != 25 {
		t.Fatalf("array = %+v", array)
	}
}

func TestCollectSensorsReadsTemperaturesAndFans(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOST_SYS", root)
	writeSysfs(t, root, map[string]string{
		"class/hwmon/hwmon0/name":        "coretemp",
		"class/hwmon/hwmon0/temp1_input": "54000",
		"class/hwmon/hwmon0/temp1_label": "Package id 0",
		"class/hwmon/hwmon0/temp1_crit":  "100000",
		"class/hwmon/hwmon1/name":        "nct6775",
		"class/hwmon/hwmon1/fan2_input":  "1180",
	})

	sensors := collectSensors()
	if len(sensors) != 2 {
		t.Fatalf("sensors = %+v", sensors)
	}
	temperature, fan := sensors[0], sensors[1]
	if temperature.SensorID != "sensor:hwmon0:temp1" || temperature.Label != "Package id 0" || temperature.Type != "temperature" ||
		temperature.Value != 54 || temperature.CriticalCelsius == nil || *temperature.CriticalCelsius != 100 {
		t.Fatalf("temperature = %+v", temperature)
	}
	if fan.Type != "fan" || fan.Value != 1180 || fan.Label != "fan2" || fan.Chip != "nct6775" {
		t.Fatalf("fan = %+v", fan)
	}
}
