//go:build linux

package metrics

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const maxSensors = 256

// collectRAID reads the state of md arrays from sysfs; a node without
// software RAID has none.
func collectRAID() []protocol.RAIDMetrics {
	directories, _ := filepath.Glob(hostfs.Sys("block", "md*", "md"))
	arrays := make([]protocol.RAIDMetrics, 0, len(directories))
	for _, directory := range directories {
		name := filepath.Base(filepath.Dir(directory))
		array := protocol.RAIDMetrics{
			DeviceID:      "storage:" + sanitizeID(name),
			Level:         sanitize(readSysfs(directory, "level"), 64),
			State:         sanitize(readSysfs(directory, "array_state"), 64),
			Disks:         atoi(readSysfs(directory, "raid_disks")),
			Degraded:      atoi(readSysfs(directory, "degraded")),
			FailedMembers: failedMembers(directory),
		}
		if action := readSysfs(directory, "sync_action"); action != "" && action != "idle" {
			array.SyncAction = sanitize(action, 64)
			array.SyncPercent = syncPercent(readSysfs(directory, "sync_completed"))
		}

		arrays = append(arrays, array)
	}

	return arrays
}

func failedMembers(directory string) []string {
	members, _ := filepath.Glob(filepath.Join(directory, "dev-*"))
	failed := make([]string, 0)
	for _, member := range members {
		if slices.Contains(strings.Split(readSysfs(member, "state"), ","), "faulty") {
			failed = append(failed, sanitize(strings.TrimPrefix(filepath.Base(member), "dev-"), 64))
		}
	}

	return failed
}

// syncPercent reads sync_completed, "done / total" in sectors.
func syncPercent(value string) *float64 {
	done, total, found := strings.Cut(value, "/")
	if !found {
		return nil
	}
	doneSectors, err := strconv.ParseFloat(strings.TrimSpace(done), 64)
	if err != nil {
		return nil
	}
	totalSectors, err := strconv.ParseFloat(strings.TrimSpace(total), 64)
	if err != nil || totalSectors <= 0 {
		return nil
	}

	result := percent(doneSectors / totalSectors * 100)

	return &result
}

// collectSensors reads temperatures and fan speeds from hwmon. Virtual
// machines usually expose none.
func collectSensors() []protocol.SensorMetrics {
	chips, _ := filepath.Glob(hostfs.Sys("class", "hwmon", "hwmon*"))
	sensors := make([]protocol.SensorMetrics, 0)
	for _, chip := range chips {
		chipName := sanitize(readSysfs(chip, "name"), 64)
		inputs, _ := filepath.Glob(filepath.Join(chip, "temp*_input"))
		fans, _ := filepath.Glob(filepath.Join(chip, "fan*_input"))
		for _, input := range append(inputs, fans...) {
			if len(sensors) == maxSensors {
				return sensors
			}
			if sensor, ok := readSensor(chip, chipName, input); ok {
				sensors = append(sensors, sensor)
			}
		}
	}

	return sensors
}

func readSensor(chip, chipName, input string) (protocol.SensorMetrics, bool) {
	attribute := strings.TrimSuffix(filepath.Base(input), "_input")
	raw, err := strconv.ParseFloat(readSysfs(chip, attribute+"_input"), 64)
	if err != nil {
		return protocol.SensorMetrics{}, false
	}

	sensor := protocol.SensorMetrics{
		SensorID: "sensor:" + filepath.Base(chip) + ":" + attribute,
		Chip:     chipName,
		Label:    sanitize(readSysfs(chip, attribute+"_label"), 64),
		Type:     "fan",
		Value:    raw,
	}
	if sensor.Label == "" {
		sensor.Label = attribute
	}
	if strings.HasPrefix(attribute, "temp") {
		// hwmon reports temperatures in millidegrees Celsius.
		sensor.Type = "temperature"
		sensor.Value = raw / 1000
		if critical, err := strconv.ParseFloat(readSysfs(chip, attribute+"_crit"), 64); err == nil && critical > 0 {
			celsius := critical / 1000
			sensor.CriticalCelsius = &celsius
		}
	}

	return sensor, true
}

func readSysfs(directory, name string) string {
	data, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

func atoi(value string) int {
	number, err := strconv.Atoi(value)
	if err != nil || number < 0 {
		return 0
	}

	return number
}
