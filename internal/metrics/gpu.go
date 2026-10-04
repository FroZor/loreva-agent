package metrics

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const maxGPUCommandOutput = 64 * 1024

var errGPUOutputTooLarge = errors.New("GPU command output is too large")

type limitedOutput struct {
	data  []byte
	limit int
}

func (output *limitedOutput) Write(data []byte) (int, error) {
	if len(output.data)+len(data) > output.limit {
		return 0, errGPUOutputTooLarge
	}

	output.data = append(output.data, data...)

	return len(data), nil
}

type nvidiaMetric struct {
	busID              string
	utilizationPercent *float64
	memoryUsedBytes    *uint64
	temperatureCelsius *float64
	powerWatts         *float64
	fanPercent         *float64
	clockHz            *uint64
}

func findNVIDIASMI(devices []gpuDevice) string {
	hasNVIDIA := false
	for _, device := range devices {
		if strings.EqualFold(strings.TrimPrefix(device.vendorID, "0x"), "10de") {
			hasNVIDIA = true
			break
		}
	}
	if !hasNVIDIA {
		return ""
	}

	for _, candidate := range nvidiaSMICandidates() {
		information, err := os.Stat(candidate)
		if err == nil && information.Mode().IsRegular() {
			return candidate
		}
	}

	return ""
}

func nvidiaSMICandidates() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe`,
			`C:\Windows\System32\nvidia-smi.exe`,
		}
	}

	return []string{
		"/usr/bin/nvidia-smi",
		"/usr/local/bin/nvidia-smi",
		"/usr/local/nvidia/bin/nvidia-smi",
	}
}

func (collector *Collector) collectGPUs(
	ctx context.Context,
	issues *[]protocol.CollectionIssue,
) []protocol.GPUMetrics {
	if len(collector.gpus) == 0 {
		return []protocol.GPUMetrics{}
	}

	result := make([]protocol.GPUMetrics, 0, len(collector.gpus))
	nvidiaIndexes := make([]int, 0, len(collector.gpus))
	for _, device := range collector.gpus {
		result = append(result, protocol.GPUMetrics{GPUID: device.id})
		if strings.EqualFold(strings.TrimPrefix(device.vendorID, "0x"), "10de") {
			nvidiaIndexes = append(nvidiaIndexes, len(result)-1)
		}
	}

	if len(nvidiaIndexes) == 0 {
		*issues = append(*issues, issue("gpus", "telemetry_not_supported"))
		return result
	}
	if collector.nvidiaSMIPath == "" {
		*issues = append(*issues, issue("gpus.nvidia", "telemetry_not_available"))
		return result
	}

	metrics, err := queryNVIDIAMetrics(ctx, collector.nvidiaSMIPath)
	if err != nil {
		*issues = append(*issues, issue("gpus.nvidia", classifyError(err)))
		return result
	}

	used := make(map[int]struct{}, len(metrics))
	for _, metric := range metrics {
		resultIndex := matchingNVIDIAIndex(collector.gpus, nvidiaIndexes, metric.busID, used)
		if resultIndex < 0 {
			continue
		}
		used[resultIndex] = struct{}{}

		result[resultIndex].UtilizationPercent = metric.utilizationPercent
		result[resultIndex].MemoryUsedBytes = metric.memoryUsedBytes
		result[resultIndex].TemperatureCelsius = metric.temperatureCelsius
		result[resultIndex].PowerWatts = metric.powerWatts
		result[resultIndex].FanPercent = metric.fanPercent
		result[resultIndex].ClockHz = metric.clockHz
	}
	if len(used) != len(nvidiaIndexes) {
		*issues = append(*issues, issue("gpus.nvidia", "partial"))
	}

	return result
}

func queryNVIDIAMetrics(ctx context.Context, executable string) ([]nvidiaMetric, error) {
	command := exec.CommandContext(
		ctx,
		executable,
		"--query-gpu=pci.bus_id,utilization.gpu,memory.used,temperature.gpu,power.draw,fan.speed,clocks.sm",
		"--format=csv,noheader,nounits",
	)
	output := limitedOutput{limit: maxGPUCommandOutput}
	command.Stdout = &output
	command.Stderr = io.Discard

	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("query NVIDIA telemetry: %w", err)
	}

	reader := csv.NewReader(strings.NewReader(string(output.data)))
	reader.FieldsPerRecord = 7
	reader.TrimLeadingSpace = true

	result := make([]nvidiaMetric, 0)
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse NVIDIA telemetry: %w", err)
		}

		metric, err := parseNVIDIAMetric(record)
		if err != nil {
			return nil, err
		}
		result = append(result, metric)
	}

	return result, nil
}

func parseNVIDIAMetric(record []string) (nvidiaMetric, error) {
	if len(record) != 7 {
		return nvidiaMetric{}, errors.New("NVIDIA telemetry record has an invalid field count")
	}

	utilization, err := optionalFloat(record[1], 1)
	if err != nil {
		return nvidiaMetric{}, err
	}
	memoryBytes, err := optionalUint(record[2], 1024*1024)
	if err != nil {
		return nvidiaMetric{}, err
	}
	temperature, err := optionalFloat(record[3], 1)
	if err != nil {
		return nvidiaMetric{}, err
	}
	power, err := optionalFloat(record[4], 1)
	if err != nil {
		return nvidiaMetric{}, err
	}
	fan, err := optionalFloat(record[5], 1)
	if err != nil {
		return nvidiaMetric{}, err
	}
	clockHz, err := optionalUint(record[6], 1_000_000)
	if err != nil {
		return nvidiaMetric{}, err
	}

	if utilization != nil {
		value := percent(*utilization)
		utilization = &value
	}
	if fan != nil {
		value := percent(*fan)
		fan = &value
	}

	return nvidiaMetric{
		busID:              normalizePCIBusID(record[0]),
		utilizationPercent: utilization,
		memoryUsedBytes:    memoryBytes,
		temperatureCelsius: temperature,
		powerWatts:         power,
		fanPercent:         fan,
		clockHz:            clockHz,
	}, nil
}

func optionalFloat(value string, multiplier float64) (*float64, error) {
	value = strings.TrimSpace(value)
	if unavailableGPUValue(value) {
		return nil, nil
	}

	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return nil, errors.New("NVIDIA telemetry contains an invalid numeric value")
	}
	parsed *= multiplier

	return &parsed, nil
}

func optionalUint(value string, multiplier uint64) (*uint64, error) {
	value = strings.TrimSpace(value)
	if unavailableGPUValue(value) {
		return nil, nil
	}

	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed > math.MaxUint64/multiplier {
		return nil, errors.New("NVIDIA telemetry contains an invalid integer value")
	}
	parsed *= multiplier

	return &parsed, nil
}

func unavailableGPUValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "n/a", "[not supported]", "not supported":
		return true
	default:
		return false
	}
}

func matchingNVIDIAIndex(
	devices []gpuDevice,
	nvidiaIndexes []int,
	busID string,
	used map[int]struct{},
) int {
	for _, index := range nvidiaIndexes {
		if _, exists := used[index]; exists {
			continue
		}
		if normalizePCIBusID(strings.TrimPrefix(devices[index].id, "gpu:")) == busID {
			return index
		}
	}

	for _, index := range nvidiaIndexes {
		if _, exists := used[index]; !exists {
			return index
		}
	}

	return -1
}

func normalizePCIBusID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	parts := strings.Split(value, ":")
	if len(parts) == 3 && len(parts[0]) > 4 {
		parts[0] = parts[0][len(parts[0])-4:]
		value = strings.Join(parts, ":")
	}

	return filepath.ToSlash(value)
}
