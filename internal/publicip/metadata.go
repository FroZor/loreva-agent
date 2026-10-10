package publicip

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
)

const metadataHost = "http://169.254.169.254"

// metadataRequest is one request to a provider's metadata service, with the
// headers that service requires.
type metadataRequest struct {
	method  string
	path    string
	headers map[string]string
}

// cloudMetadata returns the metadata lookup for the cloud the SMBIOS vendor
// and product identify, or nil when the node is not on a known cloud.
func cloudMetadata(vendor, product string) func(ctx context.Context, family string) (netip.Addr, bool) {
	paths := metadataPaths(vendor, product)
	if paths == nil {
		return nil
	}
	client := metadataClient()

	return func(ctx context.Context, family string) (netip.Addr, bool) {
		request, exists := paths[family]
		if !exists {
			return netip.Addr{}, false
		}
		headers := request.headers
		if strings.Contains(strings.ToLower(vendor), "amazon") {
			token, ok := awsToken(ctx, client)
			if !ok {
				return netip.Addr{}, false
			}
			headers = map[string]string{"X-aws-ec2-metadata-token": token}
		}

		httpRequest, err := http.NewRequestWithContext(ctx, request.method, metadataHost+request.path, nil)
		if err != nil {
			return netip.Addr{}, false
		}
		for key, value := range headers {
			httpRequest.Header.Set(key, value)
		}
		address, err := readAddress(client, httpRequest)
		if err != nil || !Public(address) || address.Is4() != (family == "ipv4") {
			return netip.Addr{}, false
		}

		return address, true
	}
}

// metadataPaths lists the documented public-address endpoints per cloud.
func metadataPaths(vendor, product string) map[string]metadataRequest {
	vendor, product = strings.ToLower(vendor), strings.ToLower(product)
	get := func(path string, headers map[string]string) metadataRequest {
		return metadataRequest{method: http.MethodGet, path: path, headers: headers}
	}

	switch {
	case strings.Contains(vendor, "amazon"):
		// IMDSv2; the session token is added per request.
		return map[string]metadataRequest{
			"ipv4": get("/latest/meta-data/public-ipv4", nil),
			"ipv6": get("/latest/meta-data/ipv6", nil),
		}
	case strings.Contains(product, "google compute engine"):
		return map[string]metadataRequest{
			"ipv4": get("/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", map[string]string{"Metadata-Flavor": "Google"}),
		}
	case strings.Contains(vendor, "microsoft") && strings.Contains(product, "virtual machine"):
		return map[string]metadataRequest{
			"ipv4": get("/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text", map[string]string{"Metadata": "true"}),
		}
	case strings.Contains(vendor, "hetzner"):
		return map[string]metadataRequest{
			"ipv4": get("/hetzner/v1/metadata/public-ipv4", nil),
		}
	case strings.Contains(vendor, "digitalocean"):
		return map[string]metadataRequest{
			"ipv4": get("/metadata/v1/interfaces/public/0/ipv4/address", nil),
			"ipv6": get("/metadata/v1/interfaces/public/0/ipv6/address", nil),
		}
	default:
		return nil
	}
}

// awsToken opens an IMDSv2 session, which EC2 requires when IMDSv1 is off.
func awsToken(ctx context.Context, client *http.Client) (string, bool) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, metadataHost+"/latest/api/token", nil)
	if err != nil {
		return "", false
	}
	request.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")

	response, err := client.Do(request)
	if err != nil {
		return "", false
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", false
	}
	token, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil || len(token) == 0 {
		return "", false
	}

	return strings.TrimSpace(string(token)), true
}
