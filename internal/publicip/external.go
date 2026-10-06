package publicip

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// service is one "what is my IP" endpoint and the company that runs it;
// agreement is counted per operator.
type service struct {
	url      string
	operator string
}

// defaultServices are the HTTPS endpoints the Datadog Agent uses for the
// same purpose (docs.datadoghq.com, Network Path setup), run by five
// different companies. ipify's dual-stack host replaces its IPv4-only one.
var defaultServices = []service{
	{url: "https://icanhazip.com", operator: "cloudflare"},
	{url: "https://ipinfo.io/ip", operator: "ipinfo"},
	{url: "https://checkip.amazonaws.com", operator: "amazon"},
	{url: "https://api64.ipify.org", operator: "ipify"},
	{url: "https://whatismyip.akamai.com", operator: "akamai"},
}

// maxAnswer bounds a service's reply; an address is at most 45 characters.
const maxAnswer = 64

// externalConsensus asks every service over the given family and returns
// the address that the most operators reported, provided at least two did
// and no other address was reported as often.
func externalConsensus(services []service) func(ctx context.Context, family string) (netip.Addr, string) {
	clients := map[string]*http.Client{"ipv4": newClient("tcp4"), "ipv6": newClient("tcp6")}

	return func(ctx context.Context, family string) (netip.Addr, string) {
		client := clients[family]
		votes := make(map[netip.Addr]map[string]struct{})
		var mu sync.Mutex
		var wait sync.WaitGroup
		for _, item := range services {
			wait.Go(func() {
				address, err := ask(ctx, client, item.url)
				if err != nil || !Public(address) || address.Is4() != (family == "ipv4") {
					return
				}
				mu.Lock()
				if votes[address] == nil {
					votes[address] = make(map[string]struct{})
				}
				votes[address][item.operator] = struct{}{}
				mu.Unlock()
			})
		}
		wait.Wait()

		return elect(votes)
	}
}

func elect(votes map[netip.Addr]map[string]struct{}) (netip.Addr, string) {
	if len(votes) == 0 {
		return netip.Addr{}, "not_available"
	}

	var best netip.Addr
	bestCount, tied := 0, false
	for address, operators := range votes {
		switch count := len(operators); {
		case count > bestCount:
			best, bestCount, tied = address, count, false
		case count == bestCount:
			tied = true
		}
	}
	switch {
	case tied || bestCount < minAgreement && len(votes) > 1:
		return netip.Addr{}, "inconsistent"
	case bestCount < minAgreement:
		// Only one operator answered; one source alone is not trusted.
		return netip.Addr{}, "unconfirmed"
	}

	return best, ""
}

// newClient returns a client that dials only the given network, ignores
// proxy settings so no proxy can rewrite the answer, never follows
// redirects, and verifies certificates as usual.
func newClient(network string) *http.Client {
	dialer := &net.Dialer{Timeout: lookupTimeout}

	return &http.Client{
		Timeout: lookupTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, address)
			},
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    lookupTimeout,
			ResponseHeaderTimeout:  lookupTimeout,
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 16 * 1024,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func ask(ctx context.Context, client *http.Client, url string) (netip.Addr, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, err
	}

	return readAddress(client, request)
}

// readAddress sends a request and parses a bare address from the reply.
func readAddress(client *http.Client, request *http.Request) (netip.Addr, error) {
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, errors.New(response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAnswer+1))
	if err != nil {
		return netip.Addr{}, err
	}
	if len(body) > maxAnswer {
		return netip.Addr{}, errors.New("answer is too long")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, err
	}

	return address.Unmap(), nil
}

// metadataClient talks to the link-local metadata service of a cloud. The
// address is fixed by the agent, so the request cannot be redirected to
// another host.
func metadataClient() *http.Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second}

	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
