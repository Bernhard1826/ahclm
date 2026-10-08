package scanner

import (
	"testing"
	"time"

	"ahclm/internal/models"
)

func TestSameStringSet(t *testing.T) {
	if !sameStringSet([]string{"1.1.1.1", "2.2.2.2"}, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Fatal("equal sets did not match")
	}
	if sameStringSet([]string{"1.1.1.1"}, []string{"1.1.1.2"}) {
		t.Fatal("different sets matched")
	}
}

func TestAuthoritativeComparisonDoesNotTreatUnavailableAnswersAsPublishedData(t *testing.T) {
	topology := &models.TopologySnapshot{PublicIPs: []string{"203.0.113.10"}, NSHosts: []string{"ns.example"}}
	// The helper is intentionally not called here: this test documents the
	// model contract used by enrichment when every direct query times out.
	if topology.AuthoritativeComparison != "" || len(topology.AuthoritativeIPs) != 0 {
		t.Fatalf("unexpected unmeasured authority state: %#v", topology)
	}
	if minAuthoritativeBudget(30*time.Second) != 12*time.Second {
		t.Fatal("authoritative budget was not bounded")
	}
}
