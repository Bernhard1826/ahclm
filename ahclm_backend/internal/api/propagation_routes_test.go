package api

import (
	"testing"

	"ahclm/internal/models"
)

func TestCDNPropagationRoutesRegister(t *testing.T) {
	h := &Handler{config: &models.Config{Server: models.ServerConfig{CORSOrigins: []string{"http://localhost:25173"}}}}
	if router := h.SetupRouter(); router == nil {
		t.Fatal("router was not created")
	}
}
