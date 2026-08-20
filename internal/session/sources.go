package session

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/sources"
)

func (r *Runner) endpoints(now time.Time) []string {
	if len(r.identity.Sources.Items) == 0 || !now.Before(r.identity.Sources.ExpiresAt) {
		return []string{r.masterEndpoint}
	}

	items := append([]protocol.SourceItem(nil), r.identity.Sources.Items...)
	sort.SliceStable(items, func(left, right int) bool {
		return items[left].Priority < items[right].Priority
	})

	endpoints := make([]string, 0, len(items)+1)

	for start := 0; start < len(items); {
		end := sourcePriorityGroupEnd(items, start)
		group := append([]protocol.SourceItem(nil), items[start:end]...)

		for len(group) > 0 {
			selected := weightedSourceIndex(group)
			endpoints = append(endpoints, group[selected].URL)
			group = append(group[:selected], group[selected+1:]...)
		}

		start = end
	}

	return append(endpoints, r.masterEndpoint)
}

func sourcePriorityGroupEnd(items []protocol.SourceItem, start int) int {
	end := start + 1

	for end < len(items) && items[end].Priority == items[start].Priority {
		end++
	}

	return end
}

func weightedSourceIndex(items []protocol.SourceItem) int {
	totalWeight := 0
	for _, item := range items {
		totalWeight += item.Weight
	}

	selectedWeight := randomInt(totalWeight)

	for index := 0; index < len(items)-1; index++ {
		if selectedWeight < items[index].Weight {
			return index
		}

		selectedWeight -= items[index].Weight
	}

	return len(items) - 1
}

func (r *Runner) applySourcesUpdate(endpoint string, pool protocol.Sources) (bool, error) {
	current := r.identity.Sources

	if pool.Generation < current.Generation {
		return false, nil
	}
	if pool.Generation == current.Generation {
		if sourcesEqual(pool, current) {
			return false, nil
		}

		return false, errors.New("portal changed sources without increasing generation")
	}
	if err := sources.Validate(pool); err != nil {
		return false, err
	}

	replacement := *r.identity
	replacement.Sources = cloneSources(pool)

	if err := r.store.ReplaceIdentity(&replacement); err != nil {
		persisted, loadErr := r.store.LoadIdentity()
		if loadErr != nil || !sourcesEqual(persisted.Sources, replacement.Sources) {
			return false, fmt.Errorf("persist source pool: %w", err)
		}

		replacement = *persisted
	}

	r.identity = &replacement

	return endpoint != r.masterEndpoint && !sourceContains(replacement.Sources, endpoint), nil
}

func cloneSources(pool protocol.Sources) protocol.Sources {
	pool.Items = append([]protocol.SourceItem(nil), pool.Items...)

	return pool
}

func sourceContains(pool protocol.Sources, endpoint string) bool {
	for _, item := range pool.Items {
		if item.URL == endpoint {
			return true
		}
	}

	return false
}

func sourcesEqual(left, right protocol.Sources) bool {
	if left.Generation != right.Generation ||
		!left.ExpiresAt.Equal(right.ExpiresAt) ||
		len(left.Items) != len(right.Items) {
		return false
	}

	for index := range left.Items {
		if left.Items[index] != right.Items[index] {
			return false
		}
	}

	return true
}
