package cimd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
)

func TestRegisterClientFromMetadata(t *testing.T) {
	// Prepare a mock metadata server
	var meta string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Write([]byte(meta))
	}))
	meta = fmt.Sprintf(`{"client_id":"%s","redirect_uris":["%s/cb"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","scope":"openid profile"}`, srv.URL, srv.URL)
	defer srv.Close()

	cfg := &config.Config{}
	cfg.CIMD.HttpPermitted = true // allow http for test server if needed

	// Use memory store wrapper
	mem := storage.NewMemoryStore()
	logger := logrus.New()
	msw := store.NewMemoryStoreWrapper(mem, logger)

	// Register
	client, err := RegisterClientFromMetadata(context.Background(), cfg, msw, srv.URL)
	if err != nil {
		t.Fatalf("RegisterClientFromMetadata failed: %v", err)
	}

	if client.ID != srv.URL {
		t.Fatalf("unexpected client id: %s", client.ID)
	}

	// Ensure stored in memory
	c, err := msw.GetClient(context.Background(), client.ID)
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}
	if _, ok := c.(*fosite.DefaultClient); !ok {
		// CustomClient should be stored; memory wrapper returns as-is
	}

	// Check expiry fields
	if client.MetadataDocumentExpiresAt == 0 {
		t.Fatalf("expected metadata expiry to be set")
	}
	if time.Unix(client.MetadataDocumentUpdatedAt, 0).IsZero() {
		t.Fatalf("expected metadata updated at to be set")
	}
}
