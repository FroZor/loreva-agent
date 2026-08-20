package enrollment

import (
	"testing"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
)

func TestValidatePortalPQRoot(t *testing.T) {
	material, err := agentcrypto.Generate("portal-root")
	if err != nil {
		t.Fatal(err)
	}

	root := agentcrypto.PublicJWK(material.MLDSAPub)
	thumbprint, err := agentcrypto.JWKThumbprint(root)
	if err != nil {
		t.Fatal(err)
	}

	if err := validatePortalPQRoot(root, ""); err != nil {
		t.Fatalf("valid root without legacy pin rejected: %v", err)
	}
	if err := validatePortalPQRoot(root, thumbprint); err != nil {
		t.Fatalf("valid root with matching legacy pin rejected: %v", err)
	}
	if err := validatePortalPQRoot(root, "different"); err == nil {
		t.Fatal("portal root with mismatched legacy pin was accepted")
	}
	if err := validatePortalPQRoot(nil, ""); err == nil {
		t.Fatal("missing portal root was accepted")
	}
}
