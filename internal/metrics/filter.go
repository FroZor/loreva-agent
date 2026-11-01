package metrics

import (
	"regexp"
	"strings"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

// virtualInterfacePrefixes name interfaces that carry no traffic of their
// own: loopback, container and VM bridges, veth pairs, and overlay tunnels.
// Their traffic is already counted on a physical interface or a container.
var virtualInterfacePrefixes = []string{
	"veth", "docker", "br-", "virbr", "vnet", "cni", "flannel", "cali", "weave", "vxlan", "kube-", "tunl", "dummy",
}

// virtualDiskPrefixes name block devices that are not whole disks: loop and
// RAM devices, zram, device-mapper, optical and floppy drives, network block
// devices.
var virtualDiskPrefixes = []string{"loop", "ram", "zram", "dm-", "sr", "fd", "nbd"}

// partitionName matches partitions of common disks, such as sda1, vdb2,
// nvme0n1p3 and mmcblk0p1.
var partitionName = regexp.MustCompile(`^((s|v|xv|h)d[a-z]+[0-9]+|nvme[0-9]+n[0-9]+p[0-9]+|mmcblk[0-9]+p[0-9]+)$`)

// keyInterfaces keeps the interfaces worth a history of their own.
func keyInterfaces(names map[string]string) map[string]string {
	result := make(map[string]string, len(names))
	for id, name := range names {
		if !virtualInterface(name) {
			result[id] = name
		}
	}

	return result
}

func virtualInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, prefix := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

// keyDisks keeps whole disks, so a write is not counted once for the disk
// and again for its partition or device-mapper volume.
func keyDisks(devices []protocol.StorageDeviceMetrics) []string {
	result := make([]string, 0, len(devices))
	for _, device := range devices {
		name := strings.TrimPrefix(device.DeviceID, "storage:")
		if virtualDisk(name) {
			continue
		}
		result = append(result, device.DeviceID)
	}

	return result
}

func virtualDisk(name string) bool {
	for _, prefix := range virtualDiskPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return partitionName.MatchString(name)
}
