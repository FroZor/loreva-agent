package metrics

import "testing"

func TestParseNVIDIAMetric(t *testing.T) {
	metric, err := parseNVIDIAMetric([]string{
		"00000000:01:00.0", "75", "2048", "62", "110.5", "40", "1800",
	})
	if err != nil {
		t.Fatal(err)
	}
	if metric.busID != "0000:01:00.0" {
		t.Fatalf("bus ID = %q", metric.busID)
	}
	if metric.utilizationPercent == nil || *metric.utilizationPercent != 75 {
		t.Fatalf("utilization = %v", metric.utilizationPercent)
	}
	if metric.memoryUsedBytes == nil || *metric.memoryUsedBytes != 2*1024*1024*1024 {
		t.Fatalf("memory used = %v", metric.memoryUsedBytes)
	}
	if metric.clockHz == nil || *metric.clockHz != 1_800_000_000 {
		t.Fatalf("clock = %v", metric.clockHz)
	}
}

func TestParseNVIDIAMetricPreservesUnsupportedValues(t *testing.T) {
	metric, err := parseNVIDIAMetric([]string{
		"0000:01:00.0", "N/A", "0", "[Not Supported]", "N/A", "N/A", "N/A",
	})
	if err != nil {
		t.Fatal(err)
	}
	if metric.utilizationPercent != nil || metric.temperatureCelsius != nil ||
		metric.powerWatts != nil || metric.fanPercent != nil || metric.clockHz != nil {
		t.Fatalf("unsupported values were emitted: %+v", metric)
	}
}
