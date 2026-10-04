package workload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/distribution/reference"

	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/strictjson"
)

const maxEggBytes = 2 << 20

type pterodactylEgg struct {
	Comment      string                   `json:"_comment"`
	Meta         pterodactylEggMeta       `json:"meta"`
	ExportedAt   string                   `json:"exported_at"`
	Name         string                   `json:"name"`
	Author       string                   `json:"author"`
	Description  string                   `json:"description"`
	Features     []string                 `json:"features"`
	DockerImages map[string]string        `json:"docker_images"`
	FileDenylist []string                 `json:"file_denylist"`
	Startup      string                   `json:"startup"`
	Config       pterodactylEggConfig     `json:"config"`
	Scripts      pterodactylEggScripts    `json:"scripts"`
	Variables    []pterodactylEggVariable `json:"variables"`
}

type pterodactylEggMeta struct {
	Version      string `json:"version"`
	UpdateURL    string `json:"update_url,omitempty"`
	ExportedFrom string `json:"exported_from,omitempty"`
}

type pterodactylEggConfig struct {
	Files   json.RawMessage `json:"files"`
	Startup json.RawMessage `json:"startup"`
	Logs    json.RawMessage `json:"logs"`
	Stop    string          `json:"stop"`
}

type pterodactylEggScripts struct {
	Installation pterodactylEggInstallation `json:"installation"`
}

type pterodactylEggInstallation struct {
	Script     string `json:"script"`
	Container  string `json:"container"`
	Entrypoint string `json:"entrypoint"`
}

type pterodactylEggVariable struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Environment  string          `json:"env_variable"`
	DefaultValue json.RawMessage `json:"default_value"`
	UserViewable bool            `json:"user_viewable"`
	UserEditable bool            `json:"user_editable"`
	Rules        string          `json:"rules"`
	FieldType    string          `json:"field_type"`
}

func (builder planBuilder) planEgg(
	ctx context.Context,
	plan *storedPlan,
	input protocol.PterodactylEggInput,
) error {
	if err := validateResources(input.Resources); err != nil {
		return err
	}
	if err := validatePorts(input.Ports); err != nil {
		return err
	}

	artifactPath, err := builder.artifacts.acquire(ctx, input.Artifact)
	if err != nil {
		return err
	}
	egg, err := loadEgg(artifactPath)
	if err != nil {
		return err
	}
	if err := validateEggInput(egg, input); err != nil {
		return err
	}
	plan.ArtifactPath = artifactPath

	plan.Steps = []protocol.WorkloadPlanStep{
		{Sequence: 1, Action: "create", Resource: "managed_volume"},
	}
	if strings.TrimSpace(egg.Scripts.Installation.Script) != "" {
		plan.Steps = append(plan.Steps,
			protocol.WorkloadPlanStep{Sequence: len(plan.Steps) + 1, Action: "install", Resource: egg.Name},
		)
		plan.Findings = append(plan.Findings, finding(
			"egg_installer_script",
			"critical",
			"Pterodactyl Egg installer executes author-supplied code with network access",
			true,
		))
	}
	plan.Steps = append(plan.Steps,
		protocol.WorkloadPlanStep{Sequence: len(plan.Steps) + 1, Action: "pull", Resource: input.DockerImage},
		protocol.WorkloadPlanStep{Sequence: len(plan.Steps) + 2, Action: "start", Resource: egg.Name},
	)

	if err := validatePinnedImage(input.DockerImage); err != nil {
		plan.Findings = append(plan.Findings, finding(
			"unpinned_image",
			"high",
			"Pterodactyl Egg runtime image is not pinned by sha256 digest",
			true,
		))
	}
	plan.Findings = deduplicateFindings(plan.Findings)

	return nil
}

func loadEgg(path string) (_ pterodactylEgg, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return pterodactylEgg{}, fmt.Errorf("open Pterodactyl Egg: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(file, maxEggBytes+1))
	if err != nil {
		return pterodactylEgg{}, fmt.Errorf("read Pterodactyl Egg: %w", err)
	}
	if len(data) == 0 || len(data) > maxEggBytes {
		return pterodactylEgg{}, fmt.Errorf("Pterodactyl Egg must be between 1 byte and %d bytes", maxEggBytes)
	}

	var egg pterodactylEgg
	if err := strictjson.Decode(data, &egg); err != nil {
		return pterodactylEgg{}, fmt.Errorf("decode Pterodactyl Egg: %w", err)
	}

	return egg, nil
}

func validateEggInput(egg pterodactylEgg, input protocol.PterodactylEggInput) error {
	if egg.Meta.Version != "PTDL_v2" {
		return fmt.Errorf("unsupported Pterodactyl Egg version %q", egg.Meta.Version)
	}
	if strings.TrimSpace(egg.Name) == "" || strings.TrimSpace(egg.Startup) == "" {
		return errors.New("Pterodactyl Egg must define name and startup")
	}
	stopCommand := strings.TrimSpace(egg.Config.Stop)
	if stopCommand == "" || len(stopCommand) > 256 || strings.ContainsAny(stopCommand, "\r\n\x00") {
		return errors.New("Pterodactyl Egg must define a single-line stop command of at most 256 bytes")
	}
	if len(egg.DockerImages) == 0 || len(egg.DockerImages) > 64 {
		return errors.New("Pterodactyl Egg docker_images must contain between 1 and 64 images")
	}
	if len(egg.Features) > 64 || len(egg.Variables) > 1024 || len(input.Variables) > 1024 {
		return errors.New("Pterodactyl Egg exceeds feature or variable limits")
	}

	imageAllowed := false
	for _, image := range egg.DockerImages {
		if imageReferenceAllowed(image, input.DockerImage) {
			imageAllowed = true
			break
		}
	}
	if !imageAllowed {
		return errors.New("selected Docker image is not declared by the Pterodactyl Egg")
	}
	script := egg.Scripts.Installation
	if strings.TrimSpace(script.Script) == "" {
		return errors.New("Pterodactyl Egg v1 execution requires an installation script")
	}
	if !imageReferenceAllowed(script.Container, input.InstallerImage) {
		return errors.New("installer_image is not a digest-pinned form of the image declared by the Egg")
	}
	if err := validatePinnedImage(input.InstallerImage); err != nil {
		return fmt.Errorf("validate installer_image: %w", err)
	}
	if containsString(egg.Features, "eula") && !containsString(input.Agreements, "minecraft_eula") {
		return errors.New("Pterodactyl Egg requires explicit minecraft_eula agreement")
	}
	if containsString(egg.Features, "eula") &&
		(strings.TrimSpace(egg.Scripts.Installation.Container) == "" ||
			strings.TrimSpace(egg.Scripts.Installation.Entrypoint) == "") {
		return errors.New("Pterodactyl Egg EULA support requires an installer container and entrypoint")
	}
	if len(input.Agreements) > 16 {
		return errors.New("Pterodactyl Egg agreements exceed 16 entries")
	}
	agreements := make(map[string]struct{}, len(input.Agreements))
	for _, agreement := range input.Agreements {
		if agreement != "minecraft_eula" {
			return fmt.Errorf("unsupported workload agreement %q", agreement)
		}
		if _, duplicate := agreements[agreement]; duplicate {
			return errors.New("Pterodactyl Egg agreements contain a duplicate")
		}
		agreements[agreement] = struct{}{}
	}

	declared := make(map[string]struct{}, len(egg.Variables))
	for _, variable := range egg.Variables {
		if !validEnvironmentName(variable.Environment) {
			return errors.New("Pterodactyl Egg contains an invalid env_variable")
		}
		if _, duplicate := declared[variable.Environment]; duplicate {
			return errors.New("Pterodactyl Egg contains duplicate env_variable values")
		}
		declared[variable.Environment] = struct{}{}
	}
	for key, value := range input.Variables {
		if _, exists := declared[key]; !exists {
			return fmt.Errorf("Pterodactyl Egg variable %q is not declared", key)
		}
		if strings.ContainsRune(value, '\x00') {
			return errors.New("Pterodactyl Egg variable contains NUL")
		}
	}
	if err := validateEggVariableRules(egg, input.Variables); err != nil {
		return err
	}

	if script := egg.Scripts.Installation; strings.TrimSpace(script.Script) != "" {
		if strings.TrimSpace(script.Container) == "" || strings.TrimSpace(script.Entrypoint) == "" {
			return errors.New("Pterodactyl Egg installer must define container and entrypoint")
		}
	}

	return nil
}

func imageReferenceAllowed(declared, selected string) bool {
	declaredReference, err := referenceWithoutDigest(declared)
	if err != nil {
		return false
	}
	selectedReference, err := referenceWithoutDigest(selected)
	if err != nil {
		return false
	}

	return declaredReference == selectedReference
}

func referenceWithoutDigest(value string) (string, error) {
	named, err := reference.ParseNormalizedNamed(value)
	if err != nil {
		return "", err
	}

	result := named.Name()
	if tagged, ok := named.(reference.Tagged); ok {
		return result + ":" + tagged.Tag(), nil
	}

	return reference.TagNameOnly(named).String(), nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}

func eggEnvironment(egg pterodactylEgg, values map[string]string) ([]string, error) {
	result := make([]string, 0, len(egg.Variables))
	for _, variable := range egg.Variables {
		value, err := eggVariableValue(variable, values)
		if err != nil {
			return nil, err
		}
		result = append(result, variable.Environment+"="+value)
	}
	sort.Strings(result)

	return result, nil
}
