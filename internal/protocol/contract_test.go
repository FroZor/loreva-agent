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
		"metricsRollup":              MetricsRollupType,
		"metricsQuery":               MetricsQueryType,
		"nodeNetworkRefresh":         NodeNetworkRefreshType,
		"nodeProcessInspect":         NodeProcessInspectType,
		"nodeProcessInspectResult":   NodeProcessInspectResultType,
		"containersList":             ContainersListType,
		"containersListResult":       ContainersListResultType,
		"containerInspect":           ContainerInspectType,
		"containerInspectResult":     ContainerInspectResultType,
		"metricsQueryResult":         MetricsQueryResultType,
		"containerLogsOpen":          ContainerLogsOpenType,
		"containerLogsOpened":        ContainerLogsOpenedType,
		"streamCredit":               StreamCreditType,
		"streamClose":                StreamCloseType,
		"containerConsoleInfo":       ContainerConsoleInfoType,
		"containerConsoleInfoResult": ContainerConsoleInfoResultType,
		"containerConsoleSend":       ContainerConsoleSendType,
		"containerConsoleSendResult": ContainerConsoleSendResultType,
		"fsList":                     FSListType,
		"fsListResult":               FSListResultType,
		"fsPathRequest":              FSStatType,
		"fsStatResult":               FSStatResultType,
		"fsChmod":                    FSChmodType,
		"fsRename":                   FSRenameType,
		"fsDelete":                   FSDeleteType,
		"fsCopy":                     FSCopyType,
		"fsArchive":                  FSArchiveType,
		"fsExtract":                  FSExtractType,
		"fsCancel":                   FSCancelType,
		"fsProgress":                 FSProgressType,
		"fsResult":                   FSResultType,
		"fsReadOpen":                 FSReadOpenType,
		"fsReadOpened":               FSReadOpenedType,
		"fsWriteOpen":                FSWriteOpenType,
		"fsWriteReady":               FSWriteReadyType,
		"fsWriteResult":              FSWriteResultType,
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
		"metricAggregate":                reflect.TypeFor[MetricAggregate](),
		"metricRollup":                   reflect.TypeFor[MetricRollup](),
		"metricRollupSeries":             reflect.TypeFor[MetricRollupSeries](),
		"metricsRollup":                  reflect.TypeFor[MetricsRollupReport](),
		"metricsQuery":                   reflect.TypeFor[MetricsQuery](),
		"nodeNetworkRefresh":             reflect.TypeFor[NodeNetworkRefresh](),
		"nodeProcessInspect":             reflect.TypeFor[NodeProcessInspect](),
		"nodeProcessInspectResult":       reflect.TypeFor[NodeProcessInspectResult](),
		"processDetails":                 reflect.TypeFor[ProcessDetails](),
		"loginSession":                   reflect.TypeFor[LoginSession](),
		"ufwConfiguration":               reflect.TypeFor[UFWConfiguration](),
		"ufwRule":                        reflect.TypeFor[UFWRule](),
		"firewalldConfiguration":         reflect.TypeFor[FirewalldConfiguration](),
		"firewalldZone":                  reflect.TypeFor[FirewalldZone](),
		"containersList":                 reflect.TypeFor[ContainersList](),
		"containersListResult":           reflect.TypeFor[ContainersListResult](),
		"containerEngine":                reflect.TypeFor[ContainerEngine](),
		"containerSummary":               reflect.TypeFor[ContainerSummary](),
		"containerPort":                  reflect.TypeFor[ContainerPort](),
		"containerInspect":               reflect.TypeFor[ContainerInspect](),
		"containerInspectResult":         reflect.TypeFor[ContainerInspectResult](),
		"containerDetails":               reflect.TypeFor[ContainerDetails](),
		"containerImage":                 reflect.TypeFor[ContainerImage](),
		"containerCommand":               reflect.TypeFor[ContainerCommand](),
		"containerStateDetails":          reflect.TypeFor[ContainerStateDetails](),
		"containerHealth":                reflect.TypeFor[ContainerHealth](),
		"containerRestartPolicy":         reflect.TypeFor[ContainerRestartPolicy](),
		"containerNetwork":               reflect.TypeFor[ContainerNetwork](),
		"containerNetworkAttachment":     reflect.TypeFor[ContainerNetworkAttachment](),
		"containerMount":                 reflect.TypeFor[ContainerMount](),
		"containerLimits":                reflect.TypeFor[ContainerLimits](),
		"containerSecurity":              reflect.TypeFor[ContainerSecurity](),
		"containerLogging":               reflect.TypeFor[ContainerLogging](),
		"containerCompose":               reflect.TypeFor[ContainerCompose](),
		"publicAddress":                  reflect.TypeFor[PublicAddress](),
		"dnsConfiguration":               reflect.TypeFor[DNSConfiguration](),
		"securityInformation":            reflect.TypeFor[SecurityInformation](),
		"sshConfiguration":               reflect.TypeFor[SSHConfiguration](),
		"securityService":                reflect.TypeFor[SecurityService](),
		"containerLogsOpen":              reflect.TypeFor[ContainerLogsOpen](),
		"containerLogsOpened":            reflect.TypeFor[ContainerLogsOpened](),
		"streamCredit":                   reflect.TypeFor[StreamCredit](),
		"streamClose":                    reflect.TypeFor[StreamClose](),
		"containerConsoleInfo":           reflect.TypeFor[ContainerConsoleInfo](),
		"containerConsoleInfoResult":     reflect.TypeFor[ContainerConsoleInfoResult](),
		"containerConsoleSend":           reflect.TypeFor[ContainerConsoleSend](),
		"containerConsoleSendResult":     reflect.TypeFor[ContainerConsoleSendResult](),
		"fsEntry":                        reflect.TypeFor[FSEntry](),
		"fsList":                         reflect.TypeFor[FSList](),
		"fsListResult":                   reflect.TypeFor[FSListResult](),
		"fsPathRequest":                  reflect.TypeFor[FSPathRequest](),
		"fsStatResult":                   reflect.TypeFor[FSStatResult](),
		"fsChmod":                        reflect.TypeFor[FSChmod](),
		"fsRename":                       reflect.TypeFor[FSRename](),
		"fsDelete":                       reflect.TypeFor[FSDelete](),
		"fsCopy":                         reflect.TypeFor[FSCopy](),
		"fsArchive":                      reflect.TypeFor[FSArchive](),
		"fsExtract":                      reflect.TypeFor[FSExtract](),
		"fsCancel":                       reflect.TypeFor[FSCancel](),
		"fsProgress":                     reflect.TypeFor[FSProgress](),
		"fsResult":                       reflect.TypeFor[FSResult](),
		"fsReadOpen":                     reflect.TypeFor[FSReadOpen](),
		"fsReadOpened":                   reflect.TypeFor[FSReadOpened](),
		"fsWriteOpen":                    reflect.TypeFor[FSWriteOpen](),
		"fsWriteReady":                   reflect.TypeFor[FSWriteReady](),
		"fsWriteResult":                  reflect.TypeFor[FSWriteResult](),
		"metricsSampleRecord":            reflect.TypeFor[MetricsSampleRecord](),
		"metricsItem":                    reflect.TypeFor[MetricsItem](),
		"metricsQueryResult":             reflect.TypeFor[MetricsQueryResult](),
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
		"cpuCacheSpecifications":         reflect.TypeFor[CPUCacheSpecifications](),
		"platformSpecifications":         reflect.TypeFor[PlatformSpecifications](),
		"numaNodeSpecifications":         reflect.TypeFor[NUMANodeSpecifications](),
		"logicalProcessorSpecifications": reflect.TypeFor[LogicalProcessorSpecifications](),
		"cpuSpecifications":              reflect.TypeFor[CPUSpecifications](),
		"memoryModuleSpecifications":     reflect.TypeFor[MemoryModuleSpecifications](),
		"memorySpecifications":           reflect.TypeFor[MemorySpecifications](),
		"gpuSpecifications":              reflect.TypeFor[GPUSpecifications](),
		"storageDeviceSpecifications":    reflect.TypeFor[StorageDeviceSpecifications](),
		"storagePartitionSpecifications": reflect.TypeFor[StoragePartitionSpecifications](),
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
		"tcpMetrics":                     reflect.TypeFor[TCPMetrics](),
		"raidMetrics":                    reflect.TypeFor[RAIDMetrics](),
		"sensorMetrics":                  reflect.TypeFor[SensorMetrics](),
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
	limitCores := 2.0
	containerID := strings.Repeat("ab", 32)
	fsEntry := FSEntry{
		Name: "server.properties", Type: "file", Size: 22, Mode: 0o644, UID: 1000, GID: 1000,
		ModifiedAt: now, Version: "1791221962324109625-22",
	}
	nodeID := "65a1876f-a715-45fc-9ac0-e4bc31067059"
	portalID := "d1b181c1-52ec-4d55-b2c9-b1428305b294"
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	syncPercent, criticalCelsius := 25.0, 100.0
	nodeMetrics := NodeMetrics{
		CPU:    CPUMetrics{Total: CPUUtilizationMetrics{UsagePercent: 10, IdlePercent: 90}, Logical: []LogicalProcessorMetrics{}},
		Memory: MemoryMetrics{TotalBytes: 1024, UsedBytes: 512, AvailableBytes: 512},
		Storage: StorageMetrics{Devices: []StorageDeviceMetrics{}, Filesystems: []FilesystemMetrics{{
			FilesystemID: "filesystem:dev-vda1", Mountpoint: "/", Device: "/dev/vda1", FilesystemType: "ext4",
			TotalBytes: 100, UsedBytes: 40, AvailableBytes: 60, UsedPercent: 40,
		}}, RAID: []RAIDMetrics{{
			DeviceID: "storage:md0", Level: "raid1", State: "clean", Disks: 2, Degraded: 1, FailedMembers: []string{"sdb1"},
			SyncAction: "recover", SyncPercent: &syncPercent,
		}}},
		Network:   []NetworkMetrics{{InterfaceID: "network:2", RXBytesTotal: 1000, TXBytesTotal: 2000}},
		TCP:       &TCPMetrics{Established: 3, TimeWait: 1, InUse: 5, PassiveOpensPerSecond: 0.5},
		GPUs:      []GPUMetrics{},
		Sensors:   []SensorMetrics{{SensorID: "sensor:hwmon0:temp1", Chip: "coretemp", Label: "Package id 0", Type: "temperature", Value: 54, CriticalCelsius: &criticalCelsius}},
		Processes: ProcessMetrics{Items: []ProcessMetric{}},
	}
	stopTimeout := 30
	exitCode := 0
	pidsLimit := int64(512)
	sizeRW := int64(4096)
	containerDetails := ContainerDetails{
		ContainerID: containerID, Name: "minecraft", CreatedAt: now, Platform: "linux",
		Image: ContainerImage{
			Reference: "itzg/minecraft-server:java21", ID: "sha256:" + strings.Repeat("cd", 32),
			Digests: []string{"itzg/minecraft-server@sha256:" + strings.Repeat("ef", 32)}, CreatedAt: &now,
			Source: "https://github.com/itzg/docker-minecraft-server",
		},
		Command: ContainerCommand{
			Path: "/start", Args: []string{}, Entrypoint: []string{"/start"}, Cmd: []string{}, WorkingDir: "/data",
			TTY: true, OpenStdin: true, StopTimeout: &stopTimeout,
		},
		Env:    []string{"EULA=TRUE", "RCON_PASSWORD=secret"},
		Labels: map[string]string{"com.docker.compose.project": "games"},
		State: ContainerStateDetails{
			Status: "running", Running: true, PID: 4242, StartedAt: &now, RestartCount: 1,
			Health: &ContainerHealth{Status: "healthy", LastExitCode: &exitCode, LastOutput: "ok"},
		},
		RestartPolicy: ContainerRestartPolicy{Name: "unless-stopped"},
		Ports:         []ContainerPort{{ContainerPort: 25565, Protocol: "tcp", HostIP: "0.0.0.0", HostPort: 25565}},
		Network: ContainerNetwork{
			Mode: "games_default", Hostname: "minecraft", DNS: []string{}, ExtraHosts: []string{},
			Networks: []ContainerNetworkAttachment{{
				Name: "games_default", NetworkID: strings.Repeat("ab", 32), IPv4Address: "172.18.0.2", IPv4Prefix: 16,
				IPv4Gateway: "172.18.0.1", MACAddress: "02:42:ac:12:00:02", Aliases: []string{"minecraft"},
			}},
		},
		Mounts: []ContainerMount{{Type: "volume", Name: "games_data", Source: "/var/lib/docker/volumes/games_data/_data", Destination: "/data", Driver: "local", ReadWrite: true}},
		Limits: ContainerLimits{MemoryBytes: 4 << 30, NanoCPUs: 2e9, PIDsLimit: &pidsLimit, ShmSizeBytes: 64 << 20},
		Security: ContainerSecurity{
			CapAdd: []string{}, CapDrop: []string{"NET_RAW"}, SecurityOptions: []string{}, Devices: []string{}, AppArmorProfile: "docker-default",
		},
		Logging:     ContainerLogging{Driver: "json-file", Options: map[string]string{"max-size": "10m"}},
		Compose:     &ContainerCompose{Project: "games", Service: "minecraft", ConfigFiles: []string{"/srv/games/compose.yaml"}},
		SizeRWBytes: &sizeRW,
	}
	rollup := MetricRollup{
		FirstSequence: 1, LastSequence: 60, Start: now, End: now.Add(time.Minute), Samples: 60,
		Series: map[string]MetricAggregate{"cpu.total.usage_percent": {Min: 1, Avg: 2, Max: 90, MaxAt: now}},
	}
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
			UFW: &UFWConfiguration{Enabled: true, DefaultIncoming: "deny", DefaultOutgoing: "allow", Rules: []UFWRule{{
				Family: "ipv4", Action: "allow", Direction: "in", Protocol: "tcp", ToAddress: "0.0.0.0/0", ToPort: "22",
				FromAddress: "203.0.113.0/24", FromPort: "any", Comment: "admin",
			}}},
			Firewalld: &FirewalldConfiguration{DefaultZone: "public", Zones: []FirewalldZone{{
				Name: "public", Target: "default", Interfaces: []string{}, Sources: []string{}, Services: []string{"ssh"},
				Ports: []string{"25565/tcp"}, RichRules: []string{},
			}}},
		},
		PublicAddresses: []PublicAddress{{Family: "ipv4", Address: "198.51.100.7", Source: "external", BehindNAT: true}},
		DNS:             &DNSConfiguration{Nameservers: []string{"127.0.0.53"}, SearchDomains: []string{}, Resolver: "systemd-resolved", Upstream: []string{"1.1.1.1"}},
		Security: SecurityInformation{
			SSH: &SSHConfiguration{
				Running: true, ConfiguredPorts: []uint16{22}, ListeningPorts: []uint16{22},
				PermitRootLogin: "prohibit-password", PasswordAuthentication: "no",
			},
			IntrusionPrevention:    []SecurityService{{Name: "fail2ban", Status: "running", Details: []string{"sshd"}}},
			MandatoryAccessControl: []SecurityService{{Name: "apparmor", Status: "enabled"}},
			Sessions: []LoginSession{{
				User: "rick", TTY: "pts/0", RemoteHost: "203.0.113.5", Service: "sshd", State: "active", StartedAt: &now, PID: 1234,
			}},
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
		ContainerLogsOpen{
			Type: ContainerLogsOpenType, RequestID: requestID, StreamID: 1, ContainerID: containerID,
			Tail: 500, Since: &now, Follow: true, Timestamps: true,
		},
		ContainerLogsOpened{Type: ContainerLogsOpenedType, RequestID: requestID, StreamID: 1, TTY: true},
		StreamCredit{Type: StreamCreditType, StreamID: 1, Bytes: MaxStreamChunkBytes},
		StreamClose{Type: StreamCloseType, StreamID: 1, Reason: StreamFailed, Code: "container_not_found"},
		StreamClose{Type: StreamCloseType, StreamID: 1, Reason: StreamCancelled},
		ContainerConsoleInfo{Type: ContainerConsoleInfoType, RequestID: requestID, ContainerID: containerID},
		ContainerConsoleInfoResult{Type: ContainerConsoleInfoResultType, RequestID: requestID, ContainerID: containerID, Adapter: "rcon"},
		ContainerConsoleSend{Type: ContainerConsoleSendType, RequestID: requestID, ContainerID: containerID, Command: "list"},
		ContainerConsoleSendResult{
			Type: ContainerConsoleSendResultType, RequestID: requestID, ContainerID: containerID,
			Adapter: "rcon", Output: "There are 0 of a max of 20 players online",
		},
		FSList{Type: FSListType, RequestID: requestID, ContainerID: containerID, Path: "/data", After: "logs"},
		FSListResult{
			Type: FSListResultType, RequestID: requestID, ContainerID: containerID, Path: "/data",
			Entries: []FSEntry{fsEntry, {Name: "data", Type: "directory", Mode: 0o755, ModifiedAt: now, Mount: true}}, More: true,
		},
		FSPathRequest{Type: FSStatType, RequestID: requestID, ContainerID: containerID, Path: "/data/server.properties"},
		FSPathRequest{Type: FSMkdirType, RequestID: requestID, ContainerID: containerID, Path: "/data/plugins"},
		FSStatResult{Type: FSStatResultType, RequestID: requestID, ContainerID: containerID, Entry: fsEntry},
		FSChmod{Type: FSChmodType, RequestID: requestID, ContainerID: containerID, Path: "/data/start.sh", Mode: 0o755},
		FSRename{Type: FSRenameType, RequestID: requestID, ContainerID: containerID, Path: "/data/a.txt", To: "/data/b.txt"},
		FSDelete{Type: FSDeleteType, RequestID: requestID, ContainerID: containerID, Paths: []string{"/data/logs"}},
		FSCopy{Type: FSCopyType, RequestID: requestID, ContainerID: containerID, Paths: []string{"/data/world"}, To: "/backup"},
		FSArchive{Type: FSArchiveType, RequestID: requestID, ContainerID: containerID, Paths: []string{"/data/world"}, To: "/data/world.zip", Format: "zip"},
		FSExtract{Type: FSExtractType, RequestID: requestID, ContainerID: containerID, Path: "/data/world.zip", To: "/data"},
		FSCancel{Type: FSCancelType, RequestID: requestID},
		FSProgress{Type: FSProgressType, RequestID: requestID, Items: 120, Bytes: 1 << 20},
		FSResult{Type: FSResultType, RequestID: requestID, ContainerID: containerID, Entry: &fsEntry, Items: 1, Bytes: 22},
		FSReadOpen{Type: FSReadOpenType, RequestID: requestID, StreamID: 3, ContainerID: containerID, Path: "/data/server.properties", Offset: 0},
		FSReadOpened{Type: FSReadOpenedType, RequestID: requestID, StreamID: 3, Entry: fsEntry, Offset: 0, Archive: false},
		FSWriteOpen{
			Type: FSWriteOpenType, RequestID: requestID, StreamID: 4, ContainerID: containerID, Path: "/data/server.properties",
			Size: 22, SHA256: strings.Repeat("a", 64), ExpectedVersion: "1791221962324109625-22",
		},
		FSWriteReady{Type: FSWriteReadyType, RequestID: requestID, StreamID: 4, Offset: 0},
		FSWriteResult{Type: FSWriteResultType, RequestID: requestID, StreamID: 4, Entry: fsEntry},
		MetricsRollupReport{
			Type: MetricsRollupType, SchemaVersion: MetricsSchemaVersion, RequestID: requestID, StreamID: portalID,
			Metric: MetricRollupSeries{Type: MetricTypeNode, Points: []MetricRollup{rollup}},
		},
		NodeNetworkRefresh{Type: NodeNetworkRefreshType, RequestID: requestID},
		NodeProcessInspect{Type: NodeProcessInspectType, RequestID: requestID, PID: 812, StartedAt: now},
		ContainersList{Type: ContainersListType, RequestID: requestID},
		ContainersListResult{
			Type: ContainersListResultType, RequestID: requestID,
			Engine: ContainerEngine{
				Runtime: "docker", Version: "29.6.2", StorageDriver: "overlayfs", CgroupVersion: "2",
				SecurityOptions: []string{"name=seccomp,profile=builtin"}, Containers: 2, ContainersRunning: 1, ContainersStopped: 1, Images: 3,
				Warnings: []string{},
			},
			Items: []ContainerSummary{{
				ContainerID: containerID, Name: "minecraft", Image: "itzg/minecraft-server:java21", ImageID: "sha256:" + strings.Repeat("cd", 32),
				State: "running", Status: "Up 3 hours", Health: "healthy", CreatedAt: now,
				Ports:          []ContainerPort{{ContainerPort: 25565, Protocol: "tcp", HostIP: "0.0.0.0", HostPort: 25565}, {ContainerPort: 25575, Protocol: "tcp"}},
				ComposeProject: "games", ComposeService: "minecraft",
			}},
		},
		ContainerInspect{Type: ContainerInspectType, RequestID: requestID, ContainerID: containerID, Size: true},
		ContainerInspectResult{Type: ContainerInspectResultType, RequestID: requestID, Container: containerDetails},
		NodeProcessInspectResult{Type: NodeProcessInspectResultType, RequestID: requestID, Process: ProcessDetails{
			PID: 812, ParentPID: 1, StartedAt: now, Name: "java", State: "sleeping", User: "minecraft",
			CommandLine: []string{"java", "-Xmx4G", "-jar", "server.jar", "nogui"},
		}},
		MetricsQuery{Type: MetricsQueryType, RequestID: requestID, From: now.Add(-time.Hour), To: now},
		MetricsQueryResult{
			Type: MetricsQueryResultType, RequestID: requestID, StreamID: portalID,
			Items: []MetricsItem{
				{Node: &rollup, Container: &rollup},
				{Sample: &MetricsSampleRecord{
					Sequence: 1, ObservedAt: now, IntervalMS: 1000, ObservationScope: ObservationScopeHost,
					Node: nodeMetrics, Containers: []ContainerMetrics{},
				}},
			},
			NextFrom: &now,
		},
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
				Containers: &ContainerMetricSet{Items: []ContainerMetrics{{
					ContainerID: "container-1", Runtime: "docker", Name: "minecraft", State: "running",
					CPU: ContainerCPUMetrics{UsagePercent: 161, OnlineCPUs: 4, LimitCores: &limitCores},
				}}},
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
