package workload

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	testWorkloadID = "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"
	testPortalID   = "d1b181c1-52ec-4d55-b2c9-b1428305b294"
	testNodeID     = "65a1876f-a715-45fc-9ac0-e4bc31067059"
)

func TestOCIPlanReportsDockerSocketFinding(t *testing.T) {
	payload := protocol.WorkloadPlanPayload{
		Format: protocol.WorkloadFormatOCI,
		OCI: &protocol.OCIWorkloadInput{
			Image:     "docker.io/library/busybox@sha256:" + repeatHex('a'),
			Resources: testResources(),
			Mounts: []protocol.WorkloadMount{{
				Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock",
			}},
		},
	}

	plan, err := (planBuilder{stateRoot: t.TempDir()}).build(t.Context(), planCommand(t, payload))
	if err != nil {
		t.Fatalf("build OCI plan: %v", err)
	}
	if len(plan.Findings) != 1 || plan.Findings[0].Code != "docker_socket" || !plan.Findings[0].RequiresApproval {
		t.Fatalf("unexpected OCI findings: %#v", plan.Findings)
	}
}

func TestComposeMinecraftPlanUsesStandardParser(t *testing.T) {
	compose, err := os.ReadFile("testdata/minecraft/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	archive := tarGzip(t, map[string][]byte{"compose.yaml": compose})
	builder, reference := artifactPlanBuilder(t, archive)
	payload := protocol.WorkloadPlanPayload{
		Format: protocol.WorkloadFormatCompose,
		Compose: &protocol.ComposeWorkloadInput{
			Artifact: reference,
			File:     "compose.yaml",
		},
	}

	plan, err := builder.build(t.Context(), planCommand(t, payload))
	if err != nil {
		t.Fatalf("build Minecraft Compose plan: %v", err)
	}
	if plan.ProjectName != composeProjectName(testWorkloadID) {
		t.Fatalf("project name = %q", plan.ProjectName)
	}
	if !hasFinding(plan.Findings, "unpinned_image") {
		t.Fatalf("Compose plan did not flag mutable image tag: %#v", plan.Findings)
	}

	project, err := composeProjectFromPlan(t.Context(), plan)
	if err != nil {
		t.Fatalf("resolve stored Minecraft Compose project: %v", err)
	}
	service := project.Services["minecraft"]
	if service.Labels[managedLabel] != "true" || service.Labels[workloadIDLabel] != testWorkloadID {
		t.Fatalf("resolved Compose project is missing Loreva ownership labels: %#v", service.Labels)
	}
	rendered, err := project.MarshalYAML()
	if err != nil {
		t.Fatalf("render stored Minecraft Compose project: %v", err)
	}
	if !strings.Contains(string(rendered), managedLabel) {
		t.Fatal("rendered Compose project does not contain Loreva ownership labels")
	}
}

func TestPterodactylPaperEggRequiresAgreementAndInstallerApproval(t *testing.T) {
	egg, err := os.ReadFile("testdata/minecraft/paper-egg.json")
	if err != nil {
		t.Fatal(err)
	}
	builder, reference := artifactPlanBuilder(t, egg)
	input := protocol.PterodactylEggInput{
		Artifact:       reference,
		DockerImage:    "ghcr.io/ptero-eggs/yolks:java_21",
		InstallerImage: "ghcr.io/ptero-eggs/installers:alpine@sha256:" + repeatHex('b'),
		Resources:      testResources(),
	}
	payload := protocol.WorkloadPlanPayload{Format: protocol.WorkloadFormatPterodactylEgg, Egg: &input}

	if _, err := builder.build(t.Context(), planCommand(t, payload)); err == nil {
		t.Fatal("Paper Egg without explicit Minecraft EULA agreement was accepted")
	}

	input.Agreements = []string{"minecraft_eula"}
	input.InstallerImage = ""
	payload.Egg = &input
	if _, err := builder.build(t.Context(), planCommand(t, payload)); err == nil {
		t.Fatal("Paper Egg without a digest-pinned installer image was accepted")
	}

	input.InstallerImage = "ghcr.io/ptero-eggs/installers:alpine@sha256:" + repeatHex('b')
	payload.Egg = &input
	plan, err := builder.build(t.Context(), planCommand(t, payload))
	if err != nil {
		t.Fatalf("build Paper Egg plan: %v", err)
	}
	if !hasFinding(plan.Findings, "egg_installer_script") || !hasFinding(plan.Findings, "unpinned_image") {
		t.Fatalf("unexpected Paper Egg findings: %#v", plan.Findings)
	}
}

func TestMinecraftDockerfilePlanRequiresBuildApproval(t *testing.T) {
	dockerfile, err := os.ReadFile("testdata/minecraft/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	archive := tarGzip(t, map[string][]byte{"Dockerfile": dockerfile})
	builder, reference := artifactPlanBuilder(t, archive)
	payload := protocol.WorkloadPlanPayload{
		Format: protocol.WorkloadFormatDockerfile,
		Dockerfile: &protocol.DockerfileWorkloadInput{
			Artifact:  reference,
			File:      "Dockerfile",
			Resources: testResources(),
			Ports: []protocol.WorkloadPort{{
				HostPort: 25565, ContainerPort: 25565, Protocol: "tcp",
			}},
		},
	}

	plan, err := builder.build(t.Context(), planCommand(t, payload))
	if err != nil {
		t.Fatalf("build Minecraft Dockerfile plan: %v", err)
	}
	if !hasFinding(plan.Findings, "dockerfile_build") {
		t.Fatalf("Dockerfile plan did not require build approval: %#v", plan.Findings)
	}
	if plan.ProjectFile != filepath.Join(plan.ProjectDir, "Dockerfile") {
		t.Fatalf("unexpected Dockerfile plan path: %s", plan.ProjectFile)
	}
}

func TestEggDeclaredImageAllowsPinnedTag(t *testing.T) {
	selected := "ghcr.io/ptero-eggs/yolks:java_21@sha256:" + repeatHex('a')
	if !imageReferenceAllowed("ghcr.io/ptero-eggs/yolks:java_21", selected) {
		t.Fatal("digest-pinned form of an Egg-declared image was rejected")
	}
	if imageReferenceAllowed("ghcr.io/ptero-eggs/yolks:java_17", selected) {
		t.Fatal("digest-pinned image with another tag was accepted")
	}
}

func TestExtractTarGzipRejectsTraversal(t *testing.T) {
	archive := tarGzip(t, map[string][]byte{"../escape": []byte("bad")})
	path := filepath.Join(t.TempDir(), "artifact.tar.gz")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(t.TempDir(), "project")
	if err := extractTarGzip(path, destination); err == nil {
		t.Fatal("archive path traversal was accepted")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed extraction left a partial project directory: %v", err)
	}
}

func TestComposeCLIEnvironmentRejectsExternalOverrides(t *testing.T) {
	t.Setenv("COMPOSE_FILE", "attacker.yaml")
	t.Setenv("DOCKER_CONTEXT", "remote-host")

	cli := composeCLI{
		dockerHost: "unix:///var/run/docker.sock",
		configDir:  t.TempDir(),
		tempDir:    t.TempDir(),
	}
	environment := strings.Join(cli.environment(), "\n")
	if strings.Contains(environment, "COMPOSE_FILE=") || strings.Contains(environment, "DOCKER_CONTEXT=") {
		t.Fatalf("unsafe Docker CLI environment override was inherited: %s", environment)
	}
	if !strings.Contains(environment, "DOCKER_HOST=unix:///var/run/docker.sock") {
		t.Fatalf("validated Docker endpoint is missing: %s", environment)
	}
}

func TestComposePreflightRejectsHostFileEscape(t *testing.T) {
	projectDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "host.env")
	if err := os.WriteFile(outsideFile, []byte("SECRET=host\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	compose := "services:\n  server:\n    image: busybox\n    env_file:\n      - " +
		strconv.Quote(filepath.ToSlash(outsideFile)) + "\n"
	composePath := filepath.Join(projectDir, "compose.yaml")
	if err := os.WriteFile(composePath, []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadComposeProject(
		t.Context(),
		projectDir,
		composePath,
		composeProjectName(testWorkloadID),
		protocol.ComposeWorkloadInput{},
	)
	if err == nil || !strings.Contains(err.Error(), "escapes the signed artifact") {
		t.Fatalf("Compose host env_file was not rejected before resolution: %v", err)
	}
}

func TestComposePreflightRejectsInclude(t *testing.T) {
	projectDir := t.TempDir()
	composePath := filepath.Join(projectDir, "compose.yaml")
	compose := "include:\n  - another.yaml\nservices:\n  server:\n    image: busybox\n"
	if err := os.WriteFile(composePath, []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadComposeProject(
		t.Context(),
		projectDir,
		composePath,
		composeProjectName(testWorkloadID),
		protocol.ComposeWorkloadInput{},
	)
	if err == nil || !strings.Contains(err.Error(), "Compose include is unsupported") {
		t.Fatalf("Compose include was not rejected during preflight: %v", err)
	}
}

func TestComposePreflightRejectsBuildContextEscape(t *testing.T) {
	projectDir := t.TempDir()
	outsideContext := t.TempDir()
	composePath := filepath.Join(projectDir, "compose.yaml")
	compose := "services:\n  server:\n    build:\n      context: " +
		strconv.Quote(filepath.ToSlash(outsideContext)) + "\n"
	if err := os.WriteFile(composePath, []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadComposeProject(
		t.Context(),
		projectDir,
		composePath,
		composeProjectName(testWorkloadID),
		protocol.ComposeWorkloadInput{},
	)
	if err == nil || !strings.Contains(err.Error(), "escapes the signed artifact") {
		t.Fatalf("Compose external build context was not rejected: %v", err)
	}
}

func artifactPlanBuilder(t *testing.T, artifact []byte) (planBuilder, protocol.ArtifactReference) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Length", strconv.Itoa(len(artifact)))
		_, _ = response.Write(artifact)
	}))
	t.Cleanup(server.Close)

	hash := sha256.Sum256(artifact)
	reference := protocol.ArtifactReference{
		ArtifactID: "6e0c1d91-5145-440f-bf97-d84db4f83644",
		SHA256:     "sha256:" + hex.EncodeToString(hash[:]),
		SizeBytes:  int64(len(artifact)),
	}
	stateRoot := t.TempDir()

	return planBuilder{
		stateRoot: stateRoot,
		artifacts: artifactStore{
			root:   filepath.Join(stateRoot, "workloads", "artifacts"),
			source: portalArtifacts{baseURL: server.URL + "/", httpClient: server.Client()},
		},
	}, reference
}

func planCommand(t *testing.T, payload protocol.WorkloadPlanPayload) protocol.WorkloadCommand {
	t.Helper()

	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	return protocol.WorkloadCommand{
		PortalID: testPortalID, NodeID: testNodeID, WorkloadID: testWorkloadID, Payload: encoded,
	}
}

func testResources() protocol.WorkloadResources {
	return protocol.WorkloadResources{CPUMillicores: 1000, MemoryBytes: 1 << 30, PIDsLimit: 512}
}

func tarGzip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	for name, content := range files {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(archive, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}

	return output.Bytes()
}

func hasFinding(findings []protocol.WorkloadFinding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code && finding.RequiresApproval {
			return true
		}
	}

	return false
}

func repeatHex(value byte) string {
	return string(bytes.Repeat([]byte{value}, 64))
}
