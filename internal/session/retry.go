package session

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

const maximumBackoff = 5 * time.Minute

func retryDelay(attempt int) time.Duration {
	maximum := 5 * time.Second

	for index := 1; index < attempt && maximum < maximumBackoff; index++ {
		maximum *= 2
		if maximum > maximumBackoff {
			maximum = maximumBackoff
		}
	}

	return randomDuration(maximum + 1)
}

func randomDuration(maximum time.Duration) time.Duration {
	if maximum <= 1 {
		return 0
	}

	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0
	}

	return time.Duration(binary.LittleEndian.Uint64(raw[:]) % uint64(maximum))
}

func randomInt(maximum int) int {
	if maximum <= 1 {
		return 0
	}

	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0
	}

	return int(binary.LittleEndian.Uint64(raw[:]) % uint64(maximum))
}
