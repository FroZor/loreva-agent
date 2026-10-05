package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
)

const (
	contractSchemaPath = "../../contract/v1/protocol.schema.json"
	contractSchemaID   = "urn:loreva:agent:wss:protocol:v1"
)

type contractDocument struct {
	Messages    []contractReference           `json:"oneOf"`
	Definitions map[string]contractDefinition `json:"$defs"`
}

type contractReference struct {
	Ref string `json:"$ref"`
}

type contractDefinition struct {
	Required   []string                   `json:"required"`
	Properties map[string]json.RawMessage `json:"properties"`
}

func TestWSSContractMatchesGoDTOs(t *testing.T) {
	document := loadContractDocument(t)

	for name, dto := range contractDTOs() {
		definition, exists := document.Definitions[name]
		if !exists {
			t.Errorf("contract definition %q is missing", name)
			continue
		}

		properties, required := jsonShape(dto)
		actualProperties := sortedKeys(definition.Properties)
		slices.Sort(definition.Required)

		if !slices.Equal(actualProperties, properties) {
			t.Errorf("contract definition %q properties = %v, Go DTO properties = %v", name, actualProperties, properties)
		}
		if !slices.Equal(definition.Required, required) {
			t.Errorf("contract definition %q required fields = %v, Go DTO required fields = %v", name, definition.Required, required)
		}
	}
}

func TestWSSContractContainsEveryMessageType(t *testing.T) {
	document := loadContractDocument(t)
	want := contractMessageTypes()
	seen := make(map[string]struct{}, len(document.Messages))

	for _, message := range document.Messages {
		const prefix = "#/$defs/"
		if !strings.HasPrefix(message.Ref, prefix) {
			t.Fatalf("top-level message reference %q is not local", message.Ref)
		}

		name := strings.TrimPrefix(message.Ref, prefix)
		messageType, exists := want[name]
		if !exists {
			t.Errorf("unexpected top-level contract message %q", name)
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			t.Errorf("duplicate top-level contract message %q", name)
			continue
		}

		seen[name] = struct{}{}
		definition := document.Definitions[name]
		var typeProperty struct {
			Const string   `json:"const"`
			Enum  []string `json:"enum"`
		}
		if err := json.Unmarshal(definition.Properties["type"], &typeProperty); err != nil {
			t.Fatalf("decode type discriminator for %q: %v", name, err)
		}
		if typeProperty.Const != messageType && !slices.Contains(typeProperty.Enum, messageType) {
			t.Errorf("contract message %q type = %q %v, want %q", name, typeProperty.Const, typeProperty.Enum, messageType)
		}
	}

	if len(seen) != len(want) {
		for name := range want {
			if _, exists := seen[name]; !exists {
				t.Errorf("message %q is not referenced by the top-level contract", name)
			}
		}
	}
}

func TestWSSContractUsesOnlyLocalReferences(t *testing.T) {
	data, err := readContractSchema()
	if err != nil {
		t.Fatal(err)
	}

	assertLocalContractReferences(t, decodeJSONValue(t, data))
}

func TestWSSContractValidatesCanonicalMessages(t *testing.T) {
	schema := compileContractSchema(t)

	for _, message := range canonicalContractMessages() {
		payload, err := json.Marshal(message)
		if err != nil {
			t.Fatalf("marshal %T: %v", message, err)
		}

		instance := decodeJSONValue(t, payload)
		if err := schema.Validate(instance); err != nil {
			t.Errorf("contract rejected canonical %T: %v", message, err)
		}

		target := reflect.New(reflect.TypeOf(message))
		if err := DecodeStrict(payload, target.Interface()); err != nil {
			t.Errorf("strict decoder rejected canonical %T: %v", message, err)
		}
	}
}

func TestWSSContractRejectsInvalidFrames(t *testing.T) {
	schema := compileContractSchema(t)
	invalid := []string{
		`{"type":"session.hello","protocol":"loreva.session.v1","peer":"device","node_id":"65a1876f-a715-45fc-9ac0-e4bc31067059","agent_version":"v1","hostname":"n","os":"linux","architecture":"amd64","portal_enrolled":false,"time":"2030-01-02T03:04:05Z"}`,
		`{"type":"pairing.result","pairing_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","status":"approved"}`,
		`{"type":"artifact.upload.result","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","state":"stored","code":"invalid_artifact"}`,
		`{"type":"workload.plan.request","schema_version":1,"request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","workload_id":"6e0c1d91-5145-440f-bf97-d84db4f83644","payload":{"timeout_seconds":30}}`,
		`{"type":"connect.accepted","unexpected":true}`,
		`{"type":"unknown"}`,
		`{"type":"node.network.accepted"}`,
		`{"type":"node.network.accepted","request_id":"not-a-uuid"}`,
		`{"type":"node.specifications.report","schema_version":2}`,
		`{"type":"metrics.accepted","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","processed":1,"failed":0}`,
		`{"type":"metrics.report","schema_version":1,"batch_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}`,
		`{"type":"metrics.report","schema_version":1,"request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","stream_id":"d1b181c1-52ec-4d55-b2c9-b1428305b294","metric":{"type":"node","samples":[{"sequence":1,"observed_at":"2030-01-02T03:04:05Z","interval_ms":1000,"observation_scope":"host","plugin":{"values":{"players":1}}}]}}`,
		`{"type":"metrics.report","schema_version":1,"request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","stream_id":"d1b181c1-52ec-4d55-b2c9-b1428305b294","metric":{"type":"plugin:minecraft","schema_version":1,"source_id":"container:server-1","samples":[{"sequence":1,"observed_at":"2030-01-02T03:04:05Z","interval_ms":1000,"observation_scope":"runtime","plugin":{"values":{}}}]}}`,
		`{"type":"sources.update","sources":{"generation":1,"expires_at":"2030-01-02T03:04:05Z","items":[{"url":"https://gateway.example/agent/v1/connect","priority":0,"weight":1,"security_profile":"pqc-hybrid-v1"}]}}`,
	}

	for _, raw := range invalid {
		if err := schema.Validate(decodeJSONValue(t, []byte(raw))); err == nil {
			t.Errorf("contract accepted invalid frame: %s", raw)
		}
	}
}

func TestWSSContractBindsWorkloadTypeToPayload(t *testing.T) {
	schema := compileContractDefinition(t, "workloadCommandClaims")
	invalid := []byte(`{
		"type":"workload.plan.request",
		"schema_version":1,
		"request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		"portal_id":"d1b181c1-52ec-4d55-b2c9-b1428305b294",
		"node_id":"65a1876f-a715-45fc-9ac0-e4bc31067059",
		"workload_id":"6e0c1d91-5145-440f-bf97-d84db4f83644",
		"session_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"issued_at":"2030-01-02T03:04:05Z",
		"expires_at":"2030-01-02T03:04:35Z",
		"payload":{"timeout_seconds":30}
	}`)

	if err := schema.Validate(decodeJSONValue(t, invalid)); err == nil {
		t.Fatal("workload.plan.request accepted a stop payload")
	}
}

func loadContractDocument(t *testing.T) contractDocument {
	t.Helper()

	data, err := readContractSchema()
	if err != nil {
		t.Fatal(err)
	}

	var document contractDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode WSS contract: %v", err)
	}

	return document
}

func compileContractSchema(t *testing.T) *jsonschema.Schema {
	return compileContractDefinition(t, "")
}

func compileContractDefinition(t *testing.T, definition string) *jsonschema.Schema {
	t.Helper()

	data, err := readContractSchema()
	if err != nil {
		t.Fatal(err)
	}
	document := decodeJSONValue(t, data)

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	if err := compiler.AddResource(contractSchemaID, document); err != nil {
		t.Fatalf("add WSS contract resource: %v", err)
	}

	location := contractSchemaID
	if definition != "" {
		location += "#/$defs/" + definition
	}
	schema, err := compiler.Compile(location)
	if err != nil {
		t.Fatalf("compile WSS contract: %v", err)
	}

	return schema
}

func readContractSchema() ([]byte, error) {
	return os.ReadFile(contractSchemaPath)
}

func decodeJSONValue(t *testing.T, data []byte) any {
	t.Helper()

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode JSON value: %v", err)
	}

	return value
}

func jsonShape(dto reflect.Type) ([]string, []string) {
	if dto.Kind() == reflect.Pointer {
		dto = dto.Elem()
	}

	properties := make([]string, 0, dto.NumField())
	required := make([]string, 0, dto.NumField())

	for index := range dto.NumField() {
		field := dto.Field(index)
		if !field.IsExported() {
			continue
		}

		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}

		properties = append(properties, name)
		if options != "omitempty" {
			required = append(required, name)
		}
	}

	slices.Sort(properties)
	slices.Sort(required)

	return properties, required
}

func sortedKeys(values map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}

func assertLocalContractReferences(t *testing.T, value any) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$ref" {
				reference, ok := child.(string)
				if !ok || !strings.HasPrefix(reference, "#/$defs/") {
					t.Errorf("contract contains a non-local reference: %v", child)
				}
				continue
			}

			assertLocalContractReferences(t, child)
		}
	case []any:
		for _, child := range typed {
			assertLocalContractReferences(t, child)
		}
	}
}

func contractMessageTypes() map[string]string {
	return map[string]string{
		"enrollmentChallenge":        EnrollmentChallenge,
		"enrollmentRequest":          EnrollmentRequestType,
		"enrollmentAccepted":         EnrollmentAcceptedType,
		"enrollmentRejected":         EnrollmentRejectedType,
		"connectChallenge":           ConnectChallenge,
		"connectProof":               ConnectProofType,
		"connectAccepted":            ConnectAcceptedType,
		"connectRejected":            ConnectRejectedType,
		"renewRequest":               RenewRequestType,
		"renewAccepted":              RenewAcceptedType,
		"renewRejected":              RenewRejectedType,
		"sourcesUpdate":              SourcesUpdateType,
		"drain":                      DrainType,
		"nodeSpecificationsReport":   NodeSpecificationsReportType,
		"nodeSpecificationsAccepted": NodeSpecificationsAcceptedType,
		"nodeSpecificationsRejected": NodeSpecificationsRejectedType,
		"nodeNetworkReport":          NodeNetworkReportType,
		"nodeNetworkAccepted":        NodeNetworkAcceptedType,
		"nodeNetworkRejected":        NodeNetworkRejectedType,
		"metricsReport":              MetricsReportType,
		"metricsAccepted":            MetricsAcceptedType,
		"metricsRejected":            MetricsRejectedType,
		"portalCommand":              PortalCommandType,
		"workloadPlanResult":         WorkloadPlanResultType,
		"workloadOperationEvent":     WorkloadOperationEventType,
		"workloadOperationResult":    WorkloadOperationResultType,
		"sessionHello":               SessionHelloType,
		"error":                      ErrorType,
		"pairingRequest":             PairingRequestType,
		"pairingStarted":             PairingStartedType,
		"pairingResult":              PairingResultType,
		"devicesList":                DevicesListType,
		"devicesListResult":          DevicesListResultType,
		"deviceRemove":               DeviceRemoveType,
		"deviceRemoveResult":         DeviceRemoveResultType,
		"deviceWorkloadCommand":      WorkloadPlanRequestType,
		"artifactUploadRequest":      ArtifactUploadRequestType,
		"artifactUploadChunk":        ArtifactUploadChunkType,
		"artifactUploadResult":       ArtifactUploadResultType,
	}
}

func contractDTOs() map[string]reflect.Type {
	return map[string]reflect.Type{
		"sessionHello":                   reflect.TypeFor[SessionHello](),
		"error":                          reflect.TypeFor[Error](),
		"pairingRequest":                 reflect.TypeFor[PairingRequest](),
		"pairingStarted":                 reflect.TypeFor[PairingStarted](),
		"pairingResult":                  reflect.TypeFor[PairingResult](),
		"devicesList":                    reflect.TypeFor[DevicesList](),
		"devicesListResult":              reflect.TypeFor[DevicesListResult](),
		"device":                         reflect.TypeFor[Device](),
		"deviceRemove":                   reflect.TypeFor[DeviceRemove](),
		"deviceRemoveResult":             reflect.TypeFor[DeviceRemoveResult](),
		"deviceWorkloadCommand":          reflect.TypeFor[DeviceWorkloadCommand](),
		"artifactUploadRequest":          reflect.TypeFor[ArtifactUploadRequest](),
		"artifactUploadChunk":            reflect.TypeFor[ArtifactUploadChunk](),
		"artifactUploadResult":           reflect.TypeFor[ArtifactUploadResult](),
		"jwk":                            reflect.TypeFor[agentcrypto.JWK](),
		"connectChallengeClaims":         reflect.TypeFor[Challenge](),
		"agentInfo":                      reflect.TypeFor[AgentInfo](),
		"sources":                        reflect.TypeFor[Sources](),
		"sourceItem":                     reflect.TypeFor[SourceItem](),
		"enrollmentChallenge":            reflect.TypeFor[Challenge](),
		"enrollmentRequest":              reflect.TypeFor[EnrollmentRequest](),
		"enrollmentAccepted":             reflect.TypeFor[EnrollmentAccepted](),
		"enrollmentRejected":             reflect.TypeFor[Rejected](),
		"connectChallenge":               reflect.TypeFor[SignedChallenge](),
		"connectProof":                   reflect.TypeFor[ConnectProof](),
		"connectAccepted":                reflect.TypeFor[ConnectAccepted](),
		"connectRejected":                reflect.TypeFor[Rejected](),
		"renewRequest":                   reflect.TypeFor[RenewRequest](),
		"renewAccepted":                  reflect.TypeFor[RenewAccepted](),
		"renewRejected":                  reflect.TypeFor[Rejected](),
		"sourcesUpdate":                  reflect.TypeFor[SourcesUpdate](),
		"drain":                          reflect.TypeFor[Drain](),
		"portalCommand":                  reflect.TypeFor[PortalCommand](),
		"artifactReference":              reflect.TypeFor[ArtifactReference](),
		"workloadResources":              reflect.TypeFor[WorkloadResources](),
		"workloadPort":                   reflect.TypeFor[WorkloadPort](),
		"workloadMount":                  reflect.TypeFor[WorkloadMount](),
		"ociWorkloadInput":               reflect.TypeFor[OCIWorkloadInput](),
		"composeWorkloadInput":           reflect.TypeFor[ComposeWorkloadInput](),
		"dockerfileWorkloadInput":        reflect.TypeFor[DockerfileWorkloadInput](),
		"pterodactylEggInput":            reflect.TypeFor[PterodactylEggInput](),
		"workloadPlanPayload":            reflect.TypeFor[WorkloadPlanPayload](),
		"workloadExecutePayload":         reflect.TypeFor[WorkloadExecutePayload](),
		"workloadStopPayload":            reflect.TypeFor[WorkloadStopPayload](),
		"workloadDeletePayload":          reflect.TypeFor[WorkloadDeletePayload](),
		"workloadCommandClaims":          reflect.TypeFor[WorkloadCommand](),
		"workloadFinding":                reflect.TypeFor[WorkloadFinding](),
		"workloadPlanStep":               reflect.TypeFor[WorkloadPlanStep](),
		"workloadPlanResultPayload":      reflect.TypeFor[WorkloadPlanResultPayload](),
		"workloadPlanResult":             reflect.TypeFor[WorkloadPlanResult](),
		"workloadOperationEventPayload":  reflect.TypeFor[WorkloadOperationEventPayload](),
		"workloadOperationEvent":         reflect.TypeFor[WorkloadOperationEvent](),
		"workloadOperationResultPayload": reflect.TypeFor[WorkloadOperationResultPayload](),
		"workloadOperationResult":        reflect.TypeFor[WorkloadOperationResult](),
		"collectionIssue":                reflect.TypeFor[CollectionIssue](),
		"osSpecifications":               reflect.TypeFor[OSSpecifications](),
		"virtualizationSpecifications":   reflect.TypeFor[VirtualizationSpecifications](),
		"systemSpecifications":           reflect.TypeFor[SystemSpecifications](),
		"cpuPackageSpecifications":       reflect.TypeFor[CPUPackageSpecifications](),
		"numaNodeSpecifications":         reflect.TypeFor[NUMANodeSpecifications](),
		"logicalProcessorSpecifications": reflect.TypeFor[LogicalProcessorSpecifications](),
		"cpuSpecifications":              reflect.TypeFor[CPUSpecifications](),
		"memoryModuleSpecifications":     reflect.TypeFor[MemoryModuleSpecifications](),
		"memorySpecifications":           reflect.TypeFor[MemorySpecifications](),
		"gpuSpecifications":              reflect.TypeFor[GPUSpecifications](),
		"storageDeviceSpecifications":    reflect.TypeFor[StorageDeviceSpecifications](),
		"networkInterfaceSpecifications": reflect.TypeFor[NetworkInterfaceSpecifications](),
		"nodeSpecifications":             reflect.TypeFor[NodeSpecifications](),
		"nodeSpecificationsReport":       reflect.TypeFor[NodeSpecificationsReport](),
		"nodeSpecificationsAccepted":     reflect.TypeFor[NodeSpecificationsAccepted](),
		"nodeSpecificationsRejected":     reflect.TypeFor[NodeReportRejected](),
		"networkAddress":                 reflect.TypeFor[NetworkAddress](),
		"networkInterfaceConfiguration":  reflect.TypeFor[NetworkInterfaceConfiguration](),
		"networkRoute":                   reflect.TypeFor[NetworkRoute](),
		"listeningPort":                  reflect.TypeFor[ListeningPort](),
		"firewallProvider":               reflect.TypeFor[FirewallProvider](),
		"portRange":                      reflect.TypeFor[PortRange](),
		"firewallRule":                   reflect.TypeFor[FirewallRule](),
		"firewallInformation":            reflect.TypeFor[FirewallInformation](),
		"nodeNetwork":                    reflect.TypeFor[NodeNetwork](),
		"nodeNetworkReport":              reflect.TypeFor[NodeNetworkReport](),
		"nodeNetworkAccepted":            reflect.TypeFor[NodeNetworkAccepted](),
		"nodeNetworkRejected":            reflect.TypeFor[NodeReportRejected](),
		"cpuUtilizationMetrics":          reflect.TypeFor[CPUUtilizationMetrics](),
		"logicalProcessorMetrics":        reflect.TypeFor[LogicalProcessorMetrics](),
		"loadAverageMetrics":             reflect.TypeFor[LoadAverageMetrics](),
		"cpuMetrics":                     reflect.TypeFor[CPUMetrics](),
		"memoryMetrics":                  reflect.TypeFor[MemoryMetrics](),
		"storageDeviceMetrics":           reflect.TypeFor[StorageDeviceMetrics](),
		"filesystemMetrics":              reflect.TypeFor[FilesystemMetrics](),
		"storageMetrics":                 reflect.TypeFor[StorageMetrics](),
		"networkMetrics":                 reflect.TypeFor[NetworkMetrics](),
		"gpuMetrics":                     reflect.TypeFor[GPUMetrics](),
		"processMetric":                  reflect.TypeFor[ProcessMetric](),
		"processMetrics":                 reflect.TypeFor[ProcessMetrics](),
		"containerCPUMetrics":            reflect.TypeFor[ContainerCPUMetrics](),
		"containerMemoryMetrics":         reflect.TypeFor[ContainerMemoryMetrics](),
		"containerStorageMetrics":        reflect.TypeFor[ContainerStorageMetrics](),
		"containerNetworkMetrics":        reflect.TypeFor[ContainerNetworkMetrics](),
		"containerPIDMetrics":            reflect.TypeFor[ContainerPIDMetrics](),
		"containerMetrics":               reflect.TypeFor[ContainerMetrics](),
		"nodeMetrics":                    reflect.TypeFor[NodeMetrics](),
		"containerMetricSet":             reflect.TypeFor[ContainerMetricSet](),
		"pluginMetricSet":                reflect.TypeFor[PluginMetricSet](),
		"metricSample":                   reflect.TypeFor[MetricSample](),
		"metricSeries":                   reflect.TypeFor[MetricSeries](),
		"metricsReport":                  reflect.TypeFor[MetricsReport](),
		"metricsAccepted":                reflect.TypeFor[MetricsAccepted](),
		"metricsRejected":                reflect.TypeFor[NodeReportRejected](),
	}
}

func canonicalContractMessages() []any {
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	requestID := "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"
	nodeID := "65a1876f-a715-45fc-9ac0-e4bc31067059"
	portalID := "d1b181c1-52ec-4d55-b2c9-b1428305b294"
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	jws := "e30.e30.A"
	certificate := "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
	csr := "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n"
	root := &agentcrypto.JWK{Kty: "AKP", Alg: agentcrypto.MLDSAAlgorithm, Pub: strings.Repeat("A", 2603)}
	sources := Sources{Generation: 1, ExpiresAt: now.Add(time.Hour), Items: []SourceItem{}}
	challenge := Challenge{
		Type:        EnrollmentChallenge,
		ChallengeID: requestID,
		Nonce:       strings.Repeat("A", 43),
		PortalID:    portalID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(30 * time.Second),
	}
	specifications := NodeSpecifications{
		System: SystemSpecifications{
			Hostname: "node-a", Architecture: "amd64", OS: OSSpecifications{Type: "linux"},
		},
		CPU: CPUSpecifications{
			Architecture: "amd64", PhysicalCoreCount: 1, LogicalProcessorCount: 1,
			Packages: []CPUPackageSpecifications{}, NUMANodes: []NUMANodeSpecifications{},
			LogicalProcessors: []LogicalProcessorSpecifications{{ID: "0", Online: true}},
		},
		Memory:            MemorySpecifications{TotalBytes: 1024, Modules: []MemoryModuleSpecifications{}},
		GPUs:              []GPUSpecifications{},
		StorageDevices:    []StorageDeviceSpecifications{},
		NetworkInterfaces: []NetworkInterfaceSpecifications{},
	}
	network := NodeNetwork{
		Interfaces:     []NetworkInterfaceConfiguration{},
		Routes:         []NetworkRoute{},
		ListeningPorts: []ListeningPort{},
		Firewall: FirewallInformation{
			Status: "inactive", Providers: []FirewallProvider{}, Rules: []FirewallRule{},
		},
	}

	return []any{
		challenge,
		EnrollmentRequest{
			Type: EnrollmentRequestType, ProtocolVersion: Version,
			Agent: AgentInfo{Version: "v1.0.0", OS: "linux", Arch: "amd64", Hostname: "node-a", Capabilities: []string{}},
			CSR:   csr, PQPoP: jws,
		},
		EnrollmentAccepted{
			Type: EnrollmentAcceptedType, NodeID: nodeID,
			CertificateChain: []string{certificate, certificate}, PortalPQRoot: root,
			PQCredential: jws, RenewAfter: now, Sources: sources,
		},
		Rejected{Type: EnrollmentRejectedType, Code: "token_expired"},
		SignedChallenge{Type: ConnectChallenge, SignedChallenge: jws},
		ConnectProof{Type: ConnectProofType, PQCredential: jws, PQPoP: jws},
		ConnectAccepted{Type: ConnectAcceptedType},
		Rejected{Type: ConnectRejectedType, Code: "node_revoked"},
		RenewRequest{Type: RenewRequestType, CSR: csr, PQPoP: jws},
		RenewAccepted{
			Type: RenewAcceptedType, CertificateChain: []string{certificate, certificate},
			PQCredential: jws, RenewAfter: now,
		},
		Rejected{Type: RenewRejectedType, Code: "temporarily_unavailable"},
		SourcesUpdate{Type: SourcesUpdateType, Sources: sources},
		Drain{Type: DrainType},
		PortalCommand{Type: PortalCommandType, SignedCommand: jws},
		WorkloadPlanResult{
			Type: WorkloadPlanResultType, SchemaVersion: WorkloadSchemaVersion,
			RequestID: requestID, PortalID: portalID, NodeID: nodeID, WorkloadID: requestID, OccurredAt: now,
			Payload: WorkloadPlanResultPayload{
				State: "ready", PlanDigest: "sha256:" + strings.Repeat("a", 64),
				Steps: []WorkloadPlanStep{}, Findings: []WorkloadFinding{},
			},
		},
		WorkloadOperationEvent{
			Type: WorkloadOperationEventType, SchemaVersion: WorkloadSchemaVersion,
			RequestID: requestID, PortalID: portalID, NodeID: nodeID, WorkloadID: requestID, OccurredAt: now,
			Payload: WorkloadOperationEventPayload{Sequence: 1, State: "running", Step: "execute"},
		},
		WorkloadOperationResult{
			Type: WorkloadOperationResultType, SchemaVersion: WorkloadSchemaVersion,
			RequestID: requestID, PortalID: portalID, NodeID: nodeID, WorkloadID: requestID, OccurredAt: now,
			Payload: WorkloadOperationResultPayload{State: "succeeded"},
		},
		SessionHello{
			Type: SessionHelloType, Protocol: DirectSessionSubprotocol, Peer: SessionPeerDevice, DeviceID: requestID,
			NodeID: nodeID, AgentVersion: "v1.0.0", Hostname: "node", OS: "linux", Architecture: "amd64", Time: now,
		},
		SessionHello{
			Type: SessionHelloType, Protocol: DirectSessionSubprotocol, Peer: SessionPeerInvite,
			NodeID: nodeID, AgentVersion: "v1.0.0", Hostname: "node", OS: "linux", Architecture: "amd64", Time: now,
		},
		Error{Type: ErrorType, RequestID: requestID, Code: "not_found", Message: "device not found"},
		PairingRequest{
			Type: PairingRequestType, DeviceName: "laptop",
			InviteToken: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		},
		PairingStarted{Type: PairingStartedType, PairingID: requestID, NodeNonce: pin},
		PairingResult{Type: PairingResultType, PairingID: requestID, Status: PairingApproved, DeviceID: requestID},
		PairingResult{Type: PairingResultType, PairingID: requestID, Status: PairingExpired},
		DevicesList{Type: DevicesListType, RequestID: requestID},
		DevicesListResult{Type: DevicesListResultType, RequestID: requestID, Devices: []Device{{
			ID: requestID, Name: "laptop", CertificatePin: pin, PairedAt: now, Current: true,
		}}},
		DeviceRemove{Type: DeviceRemoveType, RequestID: requestID, DeviceID: requestID},
		DeviceRemoveResult{Type: DeviceRemoveResultType, RequestID: requestID, DeviceID: requestID},
		DeviceWorkloadCommand{
			Type: WorkloadStopRequestType, SchemaVersion: WorkloadSchemaVersion, RequestID: requestID,
			WorkloadID: requestID, Payload: json.RawMessage(`{"timeout_seconds":30}`),
		},
		ArtifactUploadRequest{
			Type: ArtifactUploadRequestType, RequestID: requestID, ArtifactID: requestID,
			SHA256: "sha256:" + strings.Repeat("a", 64), SizeBytes: 841,
		},
		ArtifactUploadChunk{Type: ArtifactUploadChunkType, RequestID: requestID, Offset: 0, Data: "AAAA"},
		ArtifactUploadResult{Type: ArtifactUploadResultType, RequestID: requestID, State: ArtifactStored},
		ArtifactUploadResult{Type: ArtifactUploadResultType, RequestID: requestID, State: ArtifactRejected, Code: "invalid_artifact"},
		NodeSpecificationsReport{
			Type: NodeSpecificationsReportType, SchemaVersion: NodeSpecificationsSchemaVersion,
			RequestID: requestID, ObservedAt: now, ObservationScope: ObservationScopeHost,
			Specifications: specifications,
		},
		NodeSpecificationsAccepted{Type: NodeSpecificationsAcceptedType, RequestID: requestID},
		NodeReportRejected{Type: NodeSpecificationsRejectedType, RequestID: requestID, Code: "invalid_report"},
		NodeNetworkReport{
			Type: NodeNetworkReportType, SchemaVersion: NodeNetworkSchemaVersion,
			RequestID: requestID, ObservedAt: now, ObservationScope: ObservationScopeRuntime,
			Network: network,
		},
		NodeNetworkAccepted{Type: NodeNetworkAcceptedType, RequestID: requestID},
		NodeReportRejected{Type: NodeNetworkRejectedType, RequestID: requestID, Code: "temporarily_unavailable"},
		MetricsReport{
			Type: MetricsReportType, SchemaVersion: MetricsSchemaVersion,
			RequestID: requestID, StreamID: portalID,
			Metric: MetricSeries{Type: MetricTypeNode, Samples: []MetricSample{{
				Sequence: 1, ObservedAt: now, IntervalMS: 1000, ObservationScope: ObservationScopeHost,
				Node: &NodeMetrics{
					CPU: CPUMetrics{
						Total:   CPUUtilizationMetrics{UsagePercent: 10, UserPercent: 7, SystemPercent: 3, IdlePercent: 90},
						Logical: []LogicalProcessorMetrics{{ID: "cpu:0", UsagePercent: 10, UserPercent: 7, SystemPercent: 3, IdlePercent: 90}},
					},
					Memory:  MemoryMetrics{UsedBytes: 512, AvailableBytes: 512},
					Storage: StorageMetrics{Devices: []StorageDeviceMetrics{}, Filesystems: []FilesystemMetrics{}},
					Network: []NetworkMetrics{}, GPUs: []GPUMetrics{},
					Processes: ProcessMetrics{Items: []ProcessMetric{}},
				},
			}}},
		},
		MetricsReport{
			Type: MetricsReportType, SchemaVersion: MetricsSchemaVersion,
			RequestID: requestID, StreamID: portalID,
			Metric: MetricSeries{Type: MetricTypeContainer, Samples: []MetricSample{{
				Sequence: 2, ObservedAt: now, IntervalMS: 1000, ObservationScope: ObservationScopeRuntime,
				Containers: &ContainerMetricSet{Items: []ContainerMetrics{}},
			}}},
		},
		MetricsReport{
			Type: MetricsReportType, SchemaVersion: MetricsSchemaVersion,
			RequestID: requestID, StreamID: portalID,
			Metric: MetricSeries{
				Type: "plugin:minecraft", SchemaVersion: 1, SourceID: "container:server-1",
				Samples: []MetricSample{{
					Sequence: 3, ObservedAt: now, IntervalMS: 1000, ObservationScope: ObservationScopeRuntime,
					Plugin: &PluginMetricSet{Values: map[string]float64{"players.online": 3}},
				}},
			},
		},
		MetricsAccepted{Type: MetricsAcceptedType, RequestID: requestID},
		NodeReportRejected{Type: MetricsRejectedType, RequestID: requestID, Code: "temporarily_unavailable"},
	}
}
