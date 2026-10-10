//go:build linux

package specifications

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxGPUDevices     = 64
	maxMemoryModules  = 256
	maxNUMANodes      = 1024
	maxStorageDevices = 256
	maxSysfsFileSize  = 64 * 1024
)

func collectPlatform(ctx context.Context) platformSpecifications {
	memoryModules, memoryIssues := collectLinuxMemoryModules(ctx)
	gpus, gpuIssues := collectLinuxGPUs(ctx)
	storageDevices, storageIssues := collectLinuxStorage(ctx)
	numaNodes, logicalProcessorNUMA, numaIssues := collectLinuxNUMA(ctx)
	networkInterfaces, networkIssues := collectLinuxNetworkInterfaces(ctx)
	cpuDetails, offlineProcessors := collectCPUDetails()

	issues := append(memoryIssues, gpuIssues...)
	issues = append(issues, storageIssues...)
	issues = append(issues, numaIssues...)
	issues = append(issues, networkIssues...)

	return platformSpecifications{
		cpuDetails:           cpuDetails,
		offlineProcessors:    offlineProcessors,
		platform:             collectPlatformIdentity(),
		timezone:             hostTimezone(),
		initSystem:           hostInitSystem(),
		memoryModules:        memoryModules,
		gpus:                 gpus,
		storageDevices:       storageDevices,
		numaNodes:            numaNodes,
		logicalProcessorNUMA: logicalProcessorNUMA,
		networkInterfaces:    networkInterfaces,
		issues:               issues,
	}
}

func collectLinuxMemoryModules(ctx context.Context) (
	[]protocol.MemoryModuleSpecifications,
	[]protocol.CollectionIssue,
) {
	dmiEntries := hostfs.Sys("firmware/dmi/entries")
	entries, err := os.ReadDir(dmiEntries)
	if err != nil {
		return nil, []protocol.CollectionIssue{issue("memory.modules", err)}
	}

	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name() < entries[right].Name()
	})

	modules := make([]protocol.MemoryModuleSpecifications, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, []protocol.CollectionIssue{issue("memory.modules", err)}
		}
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "17-") {
			continue
		}
		if len(modules) == maxMemoryModules {
			return modules, []protocol.CollectionIssue{{Component: "memory.modules", Code: issueTruncated}}
		}

		raw, err := readBoundedFile(filepath.Join(dmiEntries, entry.Name(), "raw"), maxSysfsFileSize)
		if err != nil {
			return nil, []protocol.CollectionIssue{issue("memory.modules", err)}
		}

		module, installed, err := parseMemoryDevice(raw, len(modules))
		if err != nil {
			return nil, []protocol.CollectionIssue{issue("memory.modules", err)}
		}
		if installed {
			modules = append(modules, module)
		}
	}

	return modules, nil
}

func collectLinuxGPUs(ctx context.Context) ([]protocol.GPUSpecifications, []protocol.CollectionIssue) {
	entries, err := os.ReadDir(hostfs.Sys("bus/pci/devices"))
	if err != nil {
		return nil, []protocol.CollectionIssue{issue("gpus", err)}
	}

	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name() < entries[right].Name()
	})

	gpus := make([]protocol.GPUSpecifications, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, []protocol.CollectionIssue{issue("gpus", err)}
		}

		devicePath := filepath.Join(hostfs.Sys("bus/pci/devices"), entry.Name())
		class, err := readTrimmedFile(filepath.Join(devicePath, "class"), 32)
		if err != nil || !isGPUClass(class) {
			continue
		}
		if len(gpus) == maxGPUDevices {
			return gpus, []protocol.CollectionIssue{{Component: "gpus", Code: issueTruncated}}
		}

		vendorID, _ := readTrimmedFile(filepath.Join(devicePath, "vendor"), 32)
		deviceID, _ := readTrimmedFile(filepath.Join(devicePath, "device"), 32)
		driver := symlinkBase(filepath.Join(devicePath, "driver"))

		gpu := protocol.GPUSpecifications{
			ID:       "gpu:" + sanitizeID(entry.Name()),
			Vendor:   pciVendorName(vendorID),
			VendorID: trimHexPrefix(vendorID),
			DeviceID: trimHexPrefix(deviceID),
			Driver:   sanitize(driver, 128),
		}
		if gpu.VendorID == "10de" {
			gpu.Model, gpu.DriverVersion = nvidiaGPU(entry.Name())
		}
		gpus = append(gpus, gpu)
	}

	return gpus, nil
}

func collectLinuxStorage(ctx context.Context) (
	[]protocol.StorageDeviceSpecifications,
	[]protocol.CollectionIssue,
) {
	entries, err := os.ReadDir(hostfs.Sys("block"))
	if err != nil {
		return nil, []protocol.CollectionIssue{issue("storage_devices", err)}
	}

	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name() < entries[right].Name()
	})

	devices := make([]protocol.StorageDeviceSpecifications, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, []protocol.CollectionIssue{issue("storage_devices", err)}
		}

		name := entry.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "fd") {
			continue
		}
		if len(devices) == maxStorageDevices {
			return devices, []protocol.CollectionIssue{{Component: "storage_devices", Code: issueTruncated}}
		}

		devicePath := filepath.Join(hostfs.Sys("block"), name)
		sectors, _ := readUint(filepath.Join(devicePath, "size"))
		blockSize, _ := readUint(filepath.Join(devicePath, "queue/logical_block_size"))
		removableValue, _ := readUint(filepath.Join(devicePath, "removable"))
		rotationalValue, _ := readUint(filepath.Join(devicePath, "queue/rotational"))

		capacity := uint64(0)
		if sectors <= math.MaxUint64/512 {
			capacity = sectors * 512
		}

		transport := symlinkBase(filepath.Join(devicePath, "device/subsystem"))
		model, _ := readTrimmedFile(filepath.Join(devicePath, "device/model"), 256)
		switch {
		case strings.HasPrefix(name, "nvme"):
			transport = "nvme"
		case strings.HasPrefix(name, "dm-"):
			// Device-mapper volumes (LVM, LUKS) are named by their mapping.
			transport = "device-mapper"
			model, _ = readTrimmedFile(filepath.Join(devicePath, "dm/name"), 256)
		case strings.HasPrefix(name, "md"):
			level, _ := readTrimmedFile(filepath.Join(devicePath, "md/level"), 32)
			transport = strings.TrimSuffix("md:"+level, ":")
		}

		removable := removableValue == 1
		mediaType := "ssd"
		target, _ := filepath.EvalSymlinks(devicePath)
		switch {
		case strings.Contains(filepath.ToSlash(target), "/virtual/"), paravirtualTransports[transport]:
			// A paravirtual disk's rotational flag is whatever the
			// hypervisor sets, often 1 for SSD-backed storage, so the
			// medium behind it is not known.
			mediaType = "virtual"
		case removable:
			mediaType = "removable"
		case rotationalValue == 1:
			mediaType = "hdd"
		}

		vendor, _ := readTrimmedFile(filepath.Join(devicePath, "device/vendor"), 128)
		if named, known := pciStorageVendors[strings.ToLower(vendor)]; known {
			vendor = named
		}

		devices = append(devices, protocol.StorageDeviceSpecifications{
			ID:             "storage:" + sanitizeID(name),
			Name:           sanitize(name, 255),
			Vendor:         sanitize(vendor, 128),
			Model:          sanitize(model, 256),
			MediaType:      mediaType,
			Transport:      sanitize(transport, 64),
			CapacityBytes:  capacity,
			BlockSizeBytes: blockSize,
			Removable:      removable,
			Members:        storageMembers(devicePath),
			Partitions:     storagePartitions(devicePath, name),
		})
	}

	return devices, nil
}

// paravirtualTransports are bus subsystems of hypervisor-provided disks.
var paravirtualTransports = map[string]bool{"virtio": true, "xen": true, "vmbus": true}

// pciStorageVendors names the PCI vendor IDs that paravirtual disks report
// in place of a vendor string.
var pciStorageVendors = map[string]string{
	"0x1af4": "Red Hat, Inc. (virtio)",
	"0x15ad": "VMware",
	"0x1414": "Microsoft Corporation",
	"0x5853": "XenSource, Inc.",
}

// storageMembers lists the devices below a RAID or device-mapper volume.
func storageMembers(devicePath string) []string {
	entries, err := os.ReadDir(filepath.Join(devicePath, "slaves"))
	if err != nil {
		return nil
	}
	members := make([]string, 0, len(entries))
	for _, entry := range entries {
		members = append(members, sanitize(entry.Name(), 255))
	}

	return members
}

// storagePartitions lists the partitions of a block device; sysfs gives
// their start and size in 512-byte sectors.
func storagePartitions(devicePath, name string) []protocol.StoragePartitionSpecifications {
	entries, err := os.ReadDir(devicePath)
	if err != nil {
		return nil
	}
	var partitions []protocol.StoragePartitionSpecifications
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), name) {
			continue
		}
		partitionPath := filepath.Join(devicePath, entry.Name())
		if _, err := os.Stat(filepath.Join(partitionPath, "partition")); err != nil {
			continue
		}
		start, _ := readUint(filepath.Join(partitionPath, "start"))
		size, _ := readUint(filepath.Join(partitionPath, "size"))
		partitions = append(partitions, protocol.StoragePartitionSpecifications{
			Name:       sanitize(entry.Name(), 255),
			StartBytes: start * 512,
			SizeBytes:  size * 512,
		})
	}

	return partitions
}

func collectLinuxNUMA(ctx context.Context) (
	[]protocol.NUMANodeSpecifications,
	map[string]string,
	[]protocol.CollectionIssue,
) {
	entries, err := os.ReadDir(hostfs.Sys("devices/system/node"))
	if err != nil {
		return nil, make(map[string]string), []protocol.CollectionIssue{issue("cpu.numa_nodes", err)}
	}

	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name() < entries[right].Name()
	})

	nodes := make([]protocol.NUMANodeSpecifications, 0)
	processorNUMA := make(map[string]string)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, make(map[string]string), []protocol.CollectionIssue{issue("cpu.numa_nodes", err)}
		}
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "node") {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), "node")); err != nil {
			continue
		}
		if len(nodes) == maxNUMANodes {
			return nodes, processorNUMA, []protocol.CollectionIssue{{Component: "cpu.numa_nodes", Code: issueTruncated}}
		}

		nodeID := "numa:" + strings.TrimPrefix(entry.Name(), "node")
		nodePath := filepath.Join(hostfs.Sys("devices/system/node"), entry.Name())
		memoryBytes := readNUMAMemory(nodePath)
		nodes = append(nodes, protocol.NUMANodeSpecifications{ID: nodeID, MemoryBytes: memoryBytes})

		children, err := os.ReadDir(nodePath)
		if err != nil {
			continue
		}
		for _, child := range children {
			if !strings.HasPrefix(child.Name(), "cpu") {
				continue
			}
			processorID := strings.TrimPrefix(child.Name(), "cpu")
			if _, err := strconv.Atoi(processorID); err == nil {
				processorNUMA["cpu:"+processorID] = nodeID
			}
		}
	}

	return nodes, processorNUMA, nil
}

func collectLinuxNetworkInterfaces(ctx context.Context) (
	map[string]networkInterfaceMetadata,
	[]protocol.CollectionIssue,
) {
	entries, err := os.ReadDir(hostfs.Sys("class/net"))
	if err != nil {
		return make(map[string]networkInterfaceMetadata), []protocol.CollectionIssue{issue("network_interfaces.metadata", err)}
	}

	metadata := make(map[string]networkInterfaceMetadata, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return make(map[string]networkInterfaceMetadata), []protocol.CollectionIssue{issue("network_interfaces.metadata", err)}
		}

		interfacePath := filepath.Join(hostfs.Sys("class/net"), entry.Name())
		_, deviceErr := os.Stat(filepath.Join(interfacePath, "device"))
		driver := symlinkBase(filepath.Join(interfacePath, "device/driver"))
		driverVersion, _ := readTrimmedFile(filepath.Join(hostfs.Sys("module"), driver, "version"), 128)
		speedMbps, _ := readUint(filepath.Join(interfacePath, "speed"))
		speedBPS := uint64(0)
		if speedMbps <= math.MaxUint64/1_000_000 {
			speedBPS = speedMbps * 1_000_000
		}

		metadata[entry.Name()] = networkInterfaceMetadata{
			physicalKnown: true,
			physical:      deviceErr == nil,
			maxSpeedBPS:   speedBPS,
			driver:        sanitize(driver, 128),
			driverVersion: sanitize(driverVersion, 128),
		}
	}

	return metadata, nil
}

func parseMemoryDevice(raw []byte, index int) (protocol.MemoryModuleSpecifications, bool, error) {
	if len(raw) < 27 || raw[0] != 17 {
		return protocol.MemoryModuleSpecifications{}, false, errors.New("invalid SMBIOS memory device")
	}

	formattedLength := int(raw[1])
	if formattedLength < 27 || formattedLength > len(raw) {
		return protocol.MemoryModuleSpecifications{}, false, errors.New("invalid SMBIOS memory device length")
	}

	sizeValue := binary.LittleEndian.Uint16(raw[12:14])
	if sizeValue == 0 {
		return protocol.MemoryModuleSpecifications{}, false, nil
	}

	sizeBytes := memorySizeBytes(raw, formattedLength, sizeValue)
	if sizeBytes == 0 {
		return protocol.MemoryModuleSpecifications{}, false, nil
	}

	stringsTable := smbiosStrings(raw[formattedLength:])
	module := protocol.MemoryModuleSpecifications{
		ID:           "memory:" + strconv.Itoa(index),
		Locator:      sanitize(smbiosString(stringsTable, raw[16]), 128),
		SizeBytes:    sizeBytes,
		Type:         memoryTypeName(raw[18]),
		Manufacturer: sanitize(smbiosString(stringsTable, raw[23]), 128),
		PartNumber:   sanitize(smbiosString(stringsTable, raw[26]), 128),
	}
	if formattedLength >= 23 {
		speed := binary.LittleEndian.Uint16(raw[21:23])
		if speed != 0 && speed != math.MaxUint16 {
			module.SpeedMTS = uint64(speed)
		}
	}

	return module, true, nil
}

func memorySizeBytes(raw []byte, formattedLength int, sizeValue uint16) uint64 {
	if sizeValue == math.MaxUint16 {
		return 0
	}
	if sizeValue == 0x7fff {
		if formattedLength < 32 {
			return 0
		}
		extendedSizeMB := uint64(binary.LittleEndian.Uint32(raw[28:32]) & 0x7fffffff)
		return extendedSizeMB * 1024 * 1024
	}
	if sizeValue&0x8000 != 0 {
		return uint64(sizeValue&0x7fff) * 1024
	}

	return uint64(sizeValue) * 1024 * 1024
}

func smbiosStrings(data []byte) []string {
	end := len(data)
	for index := 0; index+1 < len(data); index++ {
		if data[index] == 0 && data[index+1] == 0 {
			end = index
			break
		}
	}
	if end == 0 {
		return nil
	}

	return strings.Split(string(data[:end]), "\x00")
}

func smbiosString(values []string, index byte) string {
	if index == 0 || int(index) > len(values) {
		return ""
	}

	return values[index-1]
}

func memoryTypeName(memoryType byte) string {
	switch memoryType {
	case 0x12:
		return "DDR"
	case 0x13:
		return "DDR2"
	case 0x18:
		return "DDR3"
	case 0x1a:
		return "DDR4"
	case 0x1b:
		return "LPDDR"
	case 0x1c:
		return "LPDDR2"
	case 0x1d:
		return "LPDDR3"
	case 0x1e:
		return "LPDDR4"
	case 0x22:
		return "DDR5"
	case 0x23:
		return "LPDDR5"
	default:
		return ""
	}
}

func readNUMAMemory(nodePath string) uint64 {
	data, err := readTrimmedFile(filepath.Join(nodePath, "meminfo"), maxSysfsFileSize)
	if err != nil {
		return 0
	}

	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "MemTotal:" {
			continue
		}

		kilobytes, err := strconv.ParseUint(fields[2], 10, 64)
		if err == nil && kilobytes <= math.MaxUint64/1024 {
			return kilobytes * 1024
		}
	}

	return 0
}

func isGPUClass(class string) bool {
	class = strings.ToLower(trimHexPrefix(class))
	return strings.HasPrefix(class, "03")
}

func pciVendorName(vendorID string) string {
	switch strings.ToLower(trimHexPrefix(vendorID)) {
	case "1002", "1022":
		return "AMD"
	case "10de":
		return "NVIDIA"
	case "8086":
		return "Intel"
	default:
		return ""
	}
}

func trimHexPrefix(value string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
}

func symlinkBase(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}

	return filepath.Base(target)
}

func readUint(path string) (uint64, error) {
	value, err := readTrimmedFile(path, 128)
	if err != nil {
		return 0, err
	}

	return strconv.ParseUint(value, 10, 64)
}

func readTrimmedFile(path string, limit int64) (string, error) {
	data, err := readBoundedFile(path, limit)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

func readBoundedFile(path string, limit int64) (data []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()

	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("system file exceeds %d bytes", limit)
	}

	return data, nil
}
