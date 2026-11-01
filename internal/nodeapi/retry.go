package nodeapi

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

const maximumBackoff = 5 * time.Minute

// RetryDelay is a random backoff for the given attempt, growing from 5
// seconds to maximumBackoff.
func RetryDelay(attempt int) time.Duration {
	maximum := 5 * time.Second

	for index := 1; index < attempt && maximum < maximumBackoff; index++ {
		maximum *= 2
		if maximum > maximumBackoff {
			maximum = maximumBackoff
		}
	}

	return RandomDuration(maximum + 1)
}

// RandomDuration returns a uniformly random duration in [0, maximum).
func RandomDuration(maximum time.Duration) time.Duration {
	if maximum <= 1 {
		return 0
	}

	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0
	}

	return time.Duration(binary.LittleEndian.Uint64(raw[:]) % uint64(maximum))
}

// RandomInt returns a uniformly random integer in [0, maximum).
func RandomInt(maximum int) int {
	if maximum <= 1 {
		return 0
	}

	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0
	}

	return int(binary.LittleEndian.Uint64(raw[:]) % uint64(maximum))
}
