package handlers

import "testing"

func TestDeviceVerificationURLUsesCompleteURI(t *testing.T) {
	got := deviceVerificationURL(map[string]interface{}{
		"verification_uri":          "https://oidc.pilot1.sram.surf.nl/device/verify",
		"verification_uri_complete": "https://oidc.pilot1.sram.surf.nl/device/verify?user_code=H7ML-D7BX",
	}, "H7ML-D7BX")
	want := "https://oidc.pilot1.sram.surf.nl/device/verify?user_code=H7ML-D7BX"
	if got != want {
		t.Fatalf("got %s", got)
	}
}

func TestDeviceVerificationURLAppendsUserCode(t *testing.T) {
	got := deviceVerificationURL(map[string]interface{}{
		"verification_uri": "https://oidc.pilot1.sram.surf.nl/device/verify",
	}, "H7ML-D7BX")
	want := "https://oidc.pilot1.sram.surf.nl/device/verify?user_code=H7ML-D7BX"
	if got != want {
		t.Fatalf("got %s", got)
	}
}

func TestDeviceVerificationURLRejectsARelativeURI(t *testing.T) {
	got := deviceVerificationURL(map[string]interface{}{
		"verification_uri": "/device",
	}, "H7ML-D7BX")
	if got != "" {
		t.Fatalf("got %s", got)
	}
}
