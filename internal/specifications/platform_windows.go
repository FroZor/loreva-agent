//go:build windows

package specifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const maxWindowsSpecificationsOutput = 4 * 1024 * 1024

const windowsSpecificationsScript = `$ErrorActionPreference = 'Stop'
$memoryAvailable = $true
$gpusAvailable = $true
$storageAvailable = $true
$networkAvailable = $true

try {
    $memory = @(CimCmdlets\Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
        [pscustomobject]@{
            locator = [string]$_.DeviceLocator
            capacity = [uint64]$_.Capacity
            type = [uint32]$_.SMBIOSMemoryType
            speed = [uint64]$_.ConfiguredClockSpeed
            manufacturer = [string]$_.Manufacturer
            part_number = [string]$_.PartNumber
        }
    })
} catch {
    $memoryAvailable = $false
    $memory = @()
}

try {
    $gpus = @(CimCmdlets\Get-CimInstance Win32_VideoController | ForEach-Object {
        [pscustomobject]@{
            pnp_device_id = [string]$_.PNPDeviceID
            vendor = [string]$_.AdapterCompatibility
            model = [string]$_.Name
            driver_version = [string]$_.DriverVersion
        }
    })
} catch {
    $gpusAvailable = $false
    $gpus = @()
}

try {
    $storage = @(CimCmdlets\Get-CimInstance Win32_DiskDrive | ForEach-Object {
        [pscustomobject]@{
            index = [uint32]$_.Index
            name = [string]$_.Caption
            vendor = [string]$_.Manufacturer
            model = [string]$_.Model
            media_type = [string]$_.MediaType
            interface_type = [string]$_.InterfaceType
            capacity = [uint64]$_.Size
            block_size = [uint64]$_.BytesPerSector
            removable = [bool]$_.RemovableMedia
        }
    })
} catch {
    $storageAvailable = $false
    $storage = @()
}

try {
    $network = @(CimCmdlets\Get-CimInstance Win32_NetworkAdapter | Where-Object { $null -ne $_.InterfaceIndex } | ForEach-Object {
        [pscustomobject]@{
            name = [string]$_.Name
            connection_name = [string]$_.NetConnectionID
            physical = [bool]$_.PhysicalAdapter
            speed = [uint64]$_.Speed
            driver = [string]$_.ServiceName
        }
    })
} catch {
    $networkAvailable = $false
    $network = @()
}

[pscustomobject]@{
    memory_available = $memoryAvailable
    gpus_available = $gpusAvailable
    storage_available = $storageAvailable
    network_available = $networkAvailable
    memory = $memory
    gpus = $gpus
    storage = $storage
    network = $network
} | ConvertTo-Json -Depth 5 -Compress`

type windowsSpecificationsDocument struct {
	MemoryAvailable  bool                    `json:"memory_available"`
	GPUsAvailable    bool                    `json:"gpus_available"`
	StorageAvailable bool                    `json:"storage_available"`
	NetworkAvailable bool                    `json:"network_available"`
	Memory           []windowsMemoryModule   `json:"memory"`
	GPUs             []windowsGPU            `json:"gpus"`
	Storage          []windowsStorageDevice  `json:"storage"`
	Network          []windowsNetworkAdapter `json:"network"`
}

type windowsMemoryModule struct {
	Locator      string `json:"locator"`
	Capacity     uint64 `json:"capacity"`
	Type         uint32 `json:"type"`
	Speed        uint64 `json:"speed"`
	Manufacturer string `json:"manufacturer"`
	PartNumber   string `json:"part_number"`
}

type windowsGPU struct {
	PNPDeviceID   string `json:"pnp_device_id"`
	Vendor        string `json:"vendor"`
	Model         string `json:"model"`
	DriverVersion string `json:"driver_version"`
}

type windowsStorageDevice struct {
	Index         uint32 `json:"index"`
	Name          string `json:"name"`
	Vendor        string `json:"vendor"`
	Model         string `json:"model"`
	MediaType     string `json:"media_type"`
	InterfaceType string `json:"interface_type"`
	Capacity      uint64 `json:"capacity"`
	BlockSize     uint64 `json:"block_size"`
	Removable     bool   `json:"removable"`
}

type windowsNetworkAdapter struct {
	Name           string `json:"name"`
	ConnectionName string `json:"connection_name"`
	Physical       bool   `json:"physical"`
	Speed          uint64 `json:"speed"`
	Driver         string `json:"driver"`
}

func collectPlatform(ctx context.Context) platformSpecifications {
	document, err := readWindowsSpecifications(ctx)
	if err != nil {
		return platformSpecifications{
			logicalProcessorNUMA: make(map[string]string),
			networkInterfaces:    make(map[string]networkInterfaceMetadata),
			issues: []protocol.CollectionIssue{
				issue("platform.windows", err),
				{Component: "cpu.numa_nodes", Code: issueNotAvailable},
				{Component: "memory.modules", Code: issueNotAvailable},
				{Component: "gpus", Code: issueNotAvailable},
				{Component: "storage_devices", Code: issueNotAvailable},
			},
		}
	}

	result := platformSpecifications{
		memoryModules:        normalizeWindowsMemory(document.Memory),
		gpus:                 normalizeWindowsGPUs(document.GPUs),
		storageDevices:       normalizeWindowsStorage(document.Storage),
		logicalProcessorNUMA: make(map[string]string),
		networkInterfaces:    normalizeWindowsNetwork(document.Network),
		issues:               []protocol.CollectionIssue{{Component: "cpu.numa_nodes", Code: issueNotAvailable}},
	}
	if len(result.gpus) > 0 {
		result.issues = append(result.issues, protocol.CollectionIssue{Component: "gpus.memory", Code: issueNotAvailable})
	}
	if !document.MemoryAvailable {
		result.memoryModules = nil
		result.issues = append(result.issues, protocol.CollectionIssue{Component: "memory.modules", Code: issueNotAvailable})
	}
	if !document.GPUsAvailable {
		result.gpus = nil
		result.issues = append(result.issues, protocol.CollectionIssue{Component: "gpus", Code: issueNotAvailable})
	}
	if !document.StorageAvailable {
		result.storageDevices = nil
		result.issues = append(result.issues, protocol.CollectionIssue{Component: "storage_devices", Code: issueNotAvailable})
	}
	if !document.NetworkAvailable {
		result.issues = append(result.issues, protocol.CollectionIssue{Component: "network_interfaces", Code: issueNotAvailable})
	}

	return result
}

func readWindowsSpecifications(ctx context.Context) (windowsSpecificationsDocument, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return windowsSpecificationsDocument{}, fmt.Errorf("locate Windows system directory: %w", err)
	}

	executable := filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	command := exec.CommandContext(
		ctx,
		executable,
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-Command", windowsSpecificationsScript,
	)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, NoInheritHandles: true}

	var stdout limitedSpecificationsBuffer
	var stderr limitedSpecificationsBuffer
	stdout.limit = maxWindowsSpecificationsOutput
	stderr.limit = 64 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return windowsSpecificationsDocument{}, contextErr
		}
		if stdout.exceeded || stderr.exceeded {
			return windowsSpecificationsDocument{}, errors.New("Windows specifications output exceeded its limit")
		}

		return windowsSpecificationsDocument{}, fmt.Errorf("run Windows specifications collector: %w", err)
	}
	if stdout.exceeded {
		return windowsSpecificationsDocument{}, errors.New("Windows specifications output exceeded its limit")
	}

	var document windowsSpecificationsDocument
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return windowsSpecificationsDocument{}, fmt.Errorf("decode Windows specifications: %w", err)
	}
	if err := finishWindowsSpecificationsJSON(decoder); err != nil {
		return windowsSpecificationsDocument{}, err
	}

	return document, nil
}

func normalizeWindowsMemory(modules []windowsMemoryModule) []protocol.MemoryModuleSpecifications {
	result := make([]protocol.MemoryModuleSpecifications, 0, len(modules))
	for index, module := range modules {
		if module.Capacity == 0 {
			continue
		}

		result = append(result, protocol.MemoryModuleSpecifications{
			ID:           "memory:" + strconv.Itoa(index),
			Locator:      sanitize(module.Locator, 128),
			SizeBytes:    module.Capacity,
			Type:         windowsMemoryType(module.Type),
			SpeedMTS:     module.Speed,
			Manufacturer: sanitize(module.Manufacturer, 128),
			PartNumber:   sanitize(module.PartNumber, 128),
		})
	}

	return result
}

func windowsMemoryType(value uint32) string {
	switch value {
	case 20:
		return "DDR"
	case 21:
		return "DDR2"
	case 24:
		return "DDR3"
	case 26:
		return "DDR4"
	case 34:
		return "DDR5"
	default:
		return ""
	}
}

func normalizeWindowsGPUs(gpus []windowsGPU) []protocol.GPUSpecifications {
	result := make([]protocol.GPUSpecifications, 0, len(gpus))
	for index, gpu := range gpus {
		vendorID, deviceID := windowsPCIIdentifiers(gpu.PNPDeviceID)
		result = append(result, protocol.GPUSpecifications{
			ID:            "gpu:" + strconv.Itoa(index),
			Vendor:        sanitize(gpu.Vendor, 128),
			Model:         sanitize(gpu.Model, 256),
			VendorID:      vendorID,
			DeviceID:      deviceID,
			DriverVersion: sanitize(gpu.DriverVersion, 128),
		})
	}

	return result
}

func windowsPCIIdentifiers(value string) (string, string) {
	upper := strings.ToUpper(value)
	return windowsPCIIdentifier(upper, "VEN_"), windowsPCIIdentifier(upper, "DEV_")
}

func windowsPCIIdentifier(value, prefix string) string {
	start := strings.Index(value, prefix)
	if start < 0 {
		return ""
	}

	start += len(prefix)
	end := start + 4
	if end > len(value) {
		return ""
	}
	for _, character := range value[start:end] {
		if !strings.ContainsRune("0123456789ABCDEF", character) {
			return ""
		}
	}

	return "0x" + strings.ToLower(value[start:end])
}

func normalizeWindowsStorage(devices []windowsStorageDevice) []protocol.StorageDeviceSpecifications {
	result := make([]protocol.StorageDeviceSpecifications, 0, len(devices))
	for _, device := range devices {
		result = append(result, protocol.StorageDeviceSpecifications{
			ID:             "disk:" + strconv.FormatUint(uint64(device.Index), 10),
			Name:           sanitize(device.Name, 256),
			Vendor:         sanitize(device.Vendor, 128),
			Model:          sanitize(device.Model, 256),
			MediaType:      normalizeWindowsMediaType(device.MediaType),
			Transport:      strings.ToLower(sanitize(device.InterfaceType, 64)),
			CapacityBytes:  device.Capacity,
			BlockSizeBytes: device.BlockSize,
			Removable:      device.Removable,
		})
	}

	return result
}

func normalizeWindowsMediaType(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "ssd"), strings.Contains(lower, "solid state"):
		return "ssd"
	case strings.Contains(lower, "removable"):
		return "removable"
	default:
		return "unknown"
	}
}

func normalizeWindowsNetwork(adapters []windowsNetworkAdapter) map[string]networkInterfaceMetadata {
	result := make(map[string]networkInterfaceMetadata, len(adapters)*2)
	for _, adapter := range adapters {
		metadata := networkInterfaceMetadata{
			physicalKnown: true,
			physical:      adapter.Physical,
			maxSpeedBPS:   adapter.Speed,
			driver:        sanitize(adapter.Driver, 128),
		}
		if name := sanitize(adapter.ConnectionName, 255); name != "" {
			result[name] = metadata
		}
		if name := sanitize(adapter.Name, 255); name != "" {
			result[name] = metadata
		}
	}

	return result
}

func finishWindowsSpecificationsJSON(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("Windows specifications collector returned multiple JSON values")
	}

	return fmt.Errorf("finish decoding Windows specifications: %w", err)
}

type limitedSpecificationsBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *limitedSpecificationsBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return originalLength, nil
	}
	if len(data) > remaining {
		buffer.exceeded = true
		data = data[:remaining]
	}

	_, _ = buffer.Buffer.Write(data)

	return originalLength, nil
}
