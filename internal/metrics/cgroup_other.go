//go:build !linux

package metrics

import (
	"context"
	"errors"
)

func findCgroupRoot() string { return "" }

func readContainerCgroup(context.Context, string, string, int, bool) (cgroupReading, error) {
	return cgroupReading{}, errors.New("cgroups are read only on Linux")
}
