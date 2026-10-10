//go:build linux

package specifications

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

// collectCPUDetails reads frequencies and caches from sysfs, per physical
// package, and the logical processors that are present but offline.
func collectCPUDetails() (map[string]cpuPackageDetails, []int) {
	root := hostfs.Sys("devices/system/cpu")
	present := parseCPUList(readOptional(filepath.Join(root, "present")))
	online := parseCPUList(readOptional(filepath.Join(root, "online")))

	details := make(map[string]cpuPackageDetails)
	// Cache instances are told apart by the set of processors sharing them.
	instances := make(map[string]map[string]map[string]struct{})
	for _, processor := range online {
		directory := filepath.Join(root, "cpu"+strconv.Itoa(processor))
		packageID := readOptional(filepath.Join(directory, "topology/physical_package_id"))
		if packageID == "" || packageID == "-1" {
			packageID = "0"
		}
		item, known := details[packageID]
		if !known {
			item.baseFrequencyHz = readKHz(filepath.Join(directory, "cpufreq/base_frequency"))
			item.minFrequencyHz = readKHz(filepath.Join(directory, "cpufreq/cpuinfo_min_freq"))
			item.maxFrequencyHz = readKHz(filepath.Join(directory, "cpufreq/cpuinfo_max_freq"))
			instances[packageID] = make(map[string]map[string]struct{})
		}

		indexes, _ := filepath.Glob(filepath.Join(directory, "cache/index*"))
		for _, index := range indexes {
			level, err := strconv.Atoi(readOptional(filepath.Join(index, "level")))
			if err != nil {
				continue
			}
			cacheType := strings.ToLower(readOptional(filepath.Join(index, "type")))
			size := parseCacheSize(readOptional(filepath.Join(index, "size")))
			shared := readOptional(filepath.Join(index, "shared_cpu_list"))
			key := strconv.Itoa(level) + "/" + cacheType
			if instances[packageID][key] == nil {
				instances[packageID][key] = make(map[string]struct{})
				item.caches = append(item.caches, protocol.CPUCacheSpecifications{
					Level:                     level,
					Type:                      sanitize(cacheType, 32),
					SizeBytes:                 size,
					SharedByLogicalProcessors: max(len(parseCPUList(shared)), 1),
				})
			}
			instances[packageID][key][shared] = struct{}{}
		}
		details[packageID] = item
	}

	for packageID, item := range details {
		for index := range item.caches {
			cache := &item.caches[index]
			cache.Instances = len(instances[packageID][strconv.Itoa(cache.Level)+"/"+cache.Type])
		}
		slices.SortFunc(item.caches, func(left, right protocol.CPUCacheSpecifications) int {
			if left.Level != right.Level {
				return left.Level - right.Level
			}
			return strings.Compare(left.Type, right.Type)
		})
		details[packageID] = item
	}

	var offline []int
	for _, processor := range present {
		if !slices.Contains(online, processor) {
			offline = append(offline, processor)
		}
	}

	return details, offline
}

// parseCPUList parses the kernel's list format, such as "0-3,8,10-11".
func parseCPUList(value string) []int {
	var result []int
	for part := range strings.SplitSeq(strings.TrimSpace(value), ",") {
		first, last, isRange := strings.Cut(part, "-")
		start, err := strconv.Atoi(first)
		if err != nil {
			continue
		}
		end := start
		if isRange {
			if end, err = strconv.Atoi(last); err != nil || end < start || end-start > 65535 {
				continue
			}
		}
		for processor := start; processor <= end; processor++ {
			result = append(result, processor)
		}
	}

	return result
}

// parseCacheSize parses sysfs cache sizes such as "32K" or "36864K".
func parseCacheSize(value string) uint64 {
	multiplier := uint64(1)
	switch {
	case strings.HasSuffix(value, "K"):
		multiplier = 1024
	case strings.HasSuffix(value, "M"):
		multiplier = 1024 * 1024
	}
	number, err := strconv.ParseUint(strings.TrimRight(value, "KM"), 10, 64)
	if err != nil {
		return 0
	}

	return number * multiplier
}

func readKHz(path string) uint64 {
	value, err := strconv.ParseUint(readOptional(path), 10, 64)
	if err != nil {
		return 0
	}

	return value * 1000
}

// collectPlatformIdentity reads the SMBIOS strings the kernel exports in
// /sys/class/dmi/id. Serial numbers and UUIDs need root and are not read.
func collectPlatformIdentity() *protocol.PlatformSpecifications {
	field := func(name string) string {
		value := sanitize(readOptional(hostfs.Sys("class/dmi/id", name)), 128)
		if placeholderDMIValue(value) {
			return ""
		}
		return value
	}

	platform := protocol.PlatformSpecifications{
		SystemVendor:  field("sys_vendor"),
		SystemProduct: field("product_name"),
		SystemVersion: field("product_version"),
		BoardVendor:   field("board_vendor"),
		BoardProduct:  field("board_name"),
		BIOSVendor:    field("bios_vendor"),
		BIOSVersion:   field("bios_version"),
		BIOSDate:      field("bios_date"),
		ChassisType:   chassisType(readOptional(hostfs.Sys("class/dmi/id/chassis_type"))),
	}
	if platform == (protocol.PlatformSpecifications{}) {
		return nil
	}

	return &platform
}

func placeholderDMIValue(value string) bool {
	switch strings.ToLower(value) {
	case "", "to be filled by o.e.m.", "default string", "not specified", "not applicable", "none", "n/a", "o.e.m.":
		return true
	}

	return false
}

// chassisType names the SMBIOS chassis types (DSP0134, system enclosure).
func chassisType(value string) string {
	names := []string{
		1: "other", 2: "unknown", 3: "desktop", 4: "low_profile_desktop", 5: "pizza_box",
		6: "mini_tower", 7: "tower", 8: "portable", 9: "laptop", 10: "notebook",
		11: "hand_held", 12: "docking_station", 13: "all_in_one", 14: "sub_notebook",
		15: "space_saving", 16: "lunch_box", 17: "main_server_chassis", 18: "expansion_chassis",
		19: "sub_chassis", 20: "bus_expansion_chassis", 21: "peripheral_chassis", 22: "raid_chassis",
		23: "rack_mount_chassis", 24: "sealed_case_pc", 25: "multi_system_chassis", 26: "compact_pci",
		27: "advanced_tca", 28: "blade", 29: "blade_enclosure", 30: "tablet", 31: "convertible",
		32: "detachable", 33: "iot_gateway", 34: "embedded_pc", 35: "mini_pc", 36: "stick_pc",
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 || number == 2 || number >= len(names) {
		return ""
	}

	return names[number]
}

// hostTimezone returns the IANA zone the host's /etc/localtime links to,
// or the content of /etc/timezone.
func hostTimezone() string {
	if target, err := os.Readlink(hostfs.Etc("localtime")); err == nil {
		if _, zone, found := strings.Cut(target, "zoneinfo/"); found {
			return sanitize(zone, 64)
		}
	}

	return sanitize(readOptional(hostfs.Etc("timezone")), 64)
}

// hostInitSystem returns the command name of the host's PID 1.
func hostInitSystem() string {
	return sanitize(readOptional(hostfs.Proc("1/comm")), 64)
}

// nvidiaGPU reads the model and driver version the NVIDIA kernel module
// publishes, without running nvidia-smi.
func nvidiaGPU(pciAddress string) (model, driverVersion string) {
	information := readOptional(hostfs.Proc("driver/nvidia/gpus", pciAddress, "information"))
	for line := range strings.SplitSeq(information, "\n") {
		if value, found := strings.CutPrefix(line, "Model:"); found {
			model = strings.TrimSpace(value)
		}
	}
	version := readOptional(hostfs.Proc("driver/nvidia/version"))
	if _, rest, found := strings.Cut(version, "Kernel Module"); found {
		if fields := strings.Fields(rest); len(fields) > 0 {
			driverVersion = fields[0]
		}
	}

	return sanitize(model, 256), sanitize(driverVersion, 64)
}

func readOptional(path string) string {
	value, _ := readTrimmedFile(path, maxSysfsFileSize)

	return value
}
