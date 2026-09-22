package scanner

import (
	"testing"

	"ahclm/internal/models"
)

func TestCymruOriginNameReversesIPv4(t *testing.T) {
	got, err := cymruOriginName("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if got != "4.3.2.1.origin.asn.cymru.com" {
		t.Fatalf("origin = %q", got)
	}
}

func TestParseDomainRDAPExtractsRegistrarAndNameservers(t *testing.T) {
	payload := map[string]any{
		"ldhName": "example.com",
		"nameservers": []any{
			map[string]any{"ldhName": "ns1.cloudflare.com."},
			map[string]any{"ldhName": "ns2.cloudflare.com."},
		},
		"entities": []any{
			map[string]any{
				"roles": []any{"registrar"},
				"vcardArray": []any{"vcard", []any{
					[]any{"fn", map[string]any{}, "text", "Cloudflare, Inc."},
				}},
			},
		},
	}
	record := parseDomainRDAP(payload, "https://rdap.org")
	if record.Registrar != "Cloudflare, Inc." {
		t.Fatalf("registrar = %q", record.Registrar)
	}
	if len(record.Nameservers) != 2 {
		t.Fatalf("nameservers = %#v", record.Nameservers)
	}
}

func TestCDNVendorFromDirectoryUsesCymruASN(t *testing.T) {
	if got := models.CDNVendorFromDirectory(13335, "CLOUDFLARENET"); got != "cloudflare" {
		t.Fatalf("got %q", got)
	}
}

func TestMergeIPDirectoryAgreesOnASN(t *testing.T) {
	record := models.IPDirectoryRecord{IPAddress: "1.1.1.1"}
	mergeIPDirectory(&record, models.IPDirectoryRecord{ASN: 13335, ASNName: "CLOUDFLARENET", Source: "cymru"})
	mergeIPDirectory(&record, models.IPDirectoryRecord{ASN: 13335, OrgName: "Cloudflare, Inc.", Source: "ripestat"})
	finalizeIPDirectory(&record)
	if record.SourceAgreement != models.DirectoryAgreementAgreed || record.ASN != 13335 {
		t.Fatalf("agreed record = %#v", record)
	}
}

func TestMergeIPDirectoryConflictIsNotProven(t *testing.T) {
	record := models.IPDirectoryRecord{IPAddress: "1.1.1.1"}
	mergeIPDirectory(&record, models.IPDirectoryRecord{ASN: 13335, Source: "cymru"})
	mergeIPDirectory(&record, models.IPDirectoryRecord{ASN: 16509, Source: "ripestat"})
	finalizeIPDirectory(&record)
	if record.SourceAgreement != models.DirectoryAgreementConflict {
		t.Fatalf("conflict record = %#v", record)
	}
}
