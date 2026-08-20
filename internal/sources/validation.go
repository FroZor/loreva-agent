// Package sources validates gateway source pools received from the portal.
package sources

import (
	"errors"
	"net/url"
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maximumItems     = 256
	maximumPriority  = 65535
	maximumWeight    = 10000
	maximumURLLength = 2048
	connectPath      = "/agent/v1/connect"
)

// Validate rejects expired, unsupported, or ambiguous source pools.
func Validate(pool protocol.Sources) error {
	if pool.Generation < 1 || !pool.ExpiresAt.After(time.Now()) || len(pool.Items) > maximumItems {
		return errors.New("portal returned invalid sources metadata")
	}

	seen := make(map[string]struct{}, len(pool.Items))

	for _, source := range pool.Items {
		if err := validateItem(source); err != nil {
			return err
		}
		if _, duplicate := seen[source.URL]; duplicate {
			return errors.New("portal returned duplicate source URLs")
		}

		seen[source.URL] = struct{}{}
	}

	return nil
}

func validateItem(source protocol.SourceItem) error {
	if source.SecurityProfile != protocol.SecurityProfile ||
		source.Priority < 0 || source.Priority > maximumPriority ||
		source.Weight <= 0 || source.Weight > maximumWeight ||
		len(source.URL) > maximumURLLength {
		return errors.New("portal returned an invalid or unsupported source")
	}

	parsed, err := url.Parse(source.URL)
	if err != nil || parsed.Scheme != "wss" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != connectPath || parsed.RawPath != "" {
		return errors.New("portal returned an invalid source URL")
	}

	return nil
}
