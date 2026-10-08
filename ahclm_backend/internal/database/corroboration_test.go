package database

import (
	"encoding/json"
	"strings"
	"testing"

	"ahclm/internal/models"
)

func TestSCTCorroborationCountsHandshakeLogs(t *testing.T) {
	scts, _ := json.Marshal([]models.SCTObservation{
		{LogID: "aa", TimestampMS: 1},
		{LogID: "bb", TimestampMS: 2},
	})
	presented, count, logs, qualified, apple, included, note := analyzeSCTCorroboration([]models.MeasurementSnapshot{{SCTJSON: string(scts)}})
	if !presented || count != 2 || logs != 2 || qualified != 0 || apple != 0 || included != 0 || note == "" {
		t.Fatalf("sct corroboration = %v %d %d %d %d %d %q", presented, count, logs, qualified, apple, included, note)
	}
}

func TestDirectoryCorroborationNamesASNs(t *testing.T) {
	raw, _ := json.Marshal(models.DirectoryObservation{
		Status: models.DirectoryIdentified,
		Endpoints: []models.IPDirectoryRecord{
			{IPAddress: "192.0.2.1", ASN: 13335, OrgName: "Cloudflare, Inc."},
		},
		Domain: &models.RDAPNameRecord{Registrar: "Cloudflare, Inc.", LDHName: "example.com"},
	})
	coverage, status, note := analyzeDirectoryCorroboration([]models.MeasurementSnapshot{{DirectoryJSON: string(raw)}})
	if coverage != 1 || status != models.DirectoryIdentified {
		t.Fatalf("directory corroboration = %f %q", coverage, status)
	}
	if note == "" {
		t.Fatal("expected a numbering-authority note")
	}
}

func TestDirectoryCorroborationConflictIsNotIdentified(t *testing.T) {
	raw, _ := json.Marshal(models.DirectoryObservation{
		Status: models.DirectoryIdentified,
		Endpoints: []models.IPDirectoryRecord{
			{IPAddress: "192.0.2.1", ASN: 13335, SourceAgreement: models.DirectoryAgreementConflict, ConflictingASNs: []int{13335, 16509}},
		},
	})
	_, status, note := analyzeDirectoryCorroboration([]models.MeasurementSnapshot{{DirectoryJSON: string(raw)}})
	if status != models.DirectoryPartial {
		t.Fatalf("status = %q, want partial", status)
	}
	if note == "" {
		t.Fatal("expected a conflict note")
	}
}

func TestSCTCorroborationNamesChromeAndAppleLists(t *testing.T) {
	scts, _ := json.Marshal([]models.SCTObservation{
		{LogID: "aa", Qualified: true, ChromeListed: true, AppleListed: true, Operator: "Google"},
	})
	presented, _, logs, qualified, apple, included, note := analyzeSCTCorroboration([]models.MeasurementSnapshot{{SCTJSON: string(scts)}})
	if !presented || logs != 1 || qualified != 1 || apple != 1 || included != 0 {
		t.Fatalf("listed sct = %v %d %d %d %d %q", presented, logs, qualified, apple, included, note)
	}
	if note == "" {
		t.Fatal("expected chrome/apple list note")
	}
}

func TestSCTCorroborationCountsInclusionProofs(t *testing.T) {
	scts, _ := json.Marshal([]models.SCTObservation{
		{LogID: "aa", Inclusion: models.SCTInclusionProven, SignatureVerified: true, STHVerified: true, ChromeListed: true, Qualified: true},
	})
	presented, _, _, _, _, included, note := analyzeSCTCorroboration([]models.MeasurementSnapshot{{SCTJSON: string(scts)}})
	if !presented || included != 1 || !strings.Contains(note, "inclusion") {
		t.Fatalf("inclusion sct = %v %d %q", presented, included, note)
	}
}

func TestCAAAuthorizesLetsEncrypt(t *testing.T) {
	status, note := models.MatchCAA([]models.CAARecord{{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}}, "C=US, O=Let's Encrypt, CN=R3")
	if status != models.CAAAuthorized {
		t.Fatalf("status = %q note=%q", status, note)
	}
}

func TestCAAUnauthorizedWhenIssuerNotListed(t *testing.T) {
	status, _ := models.MatchCAA([]models.CAARecord{{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}}, "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1")
	if status != models.CAAUnauthorized {
		t.Fatalf("status = %q", status)
	}
}

func TestNSRDAPAgreementIsProvenWhenHostsMatch(t *testing.T) {
	topology, _ := json.Marshal(models.TopologySnapshot{NSHosts: []string{"ns1.cloudflare.com."}})
	directory, _ := json.Marshal(models.DirectoryObservation{
		Domain: &models.RDAPNameRecord{Nameservers: []string{"ns1.cloudflare.com"}},
	})
	agreement, note := analyzeNSRDAPAgreement([]models.MeasurementSnapshot{{TopologyJSON: string(topology), DirectoryJSON: string(directory)}}, "")
	if agreement != models.DirectoryAgreementAgreed {
		t.Fatalf("agreement = %q note=%q", agreement, note)
	}
}
