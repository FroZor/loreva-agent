//go:build !linux

package metrics

func readKernelCounters() (kernelCounters, bool) {
	return kernelCounters{}, false
}
