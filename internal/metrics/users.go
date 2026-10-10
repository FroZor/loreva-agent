package metrics

import (
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/procfs"
)

// userCache keeps the host's UID to name map, re-read once a minute so new
// accounts appear without a restart.
type userCache struct {
	mu     sync.Mutex
	names  map[uint32]string
	readAt time.Time
}

func (c *userCache) get() map[uint32]string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.names == nil || time.Since(c.readAt) > time.Minute {
		c.names = procfs.Users()
		c.readAt = time.Now()
	}

	return c.names
}
