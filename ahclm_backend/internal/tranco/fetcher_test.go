package tranco

import (
	"strings"
	"testing"
)

func TestParseRankedCSV(t *testing.T) {
	csv := "1,google.com\n2,www.youtube.com\n3,facebook.com\n4,example.org\n"
	m := parseRankedCSV(strings.NewReader(csv), 3)

	if len(m) != 3 {
		t.Fatalf("expected 3 domains, got %d (%v)", len(m), m)
	}
	if m["google.com"] != 1 {
		t.Fatalf("google.com rank = %d, want 1", m["google.com"])
	}
	if r, ok := m["youtube.com"]; !ok || r != 2 {
		t.Fatalf("www. prefix not stripped or wrong rank: %v", m)
	}
	if _, ok := m["example.org"]; ok {
		t.Fatalf("max limit not honored, example.org should be excluded")
	}
}

func TestParseRankedCSV_SkipsHeaderAndJunk(t *testing.T) {
	csv := "rank,domain\n1,google.com\n\n#comment\n2,,\n3,cloudflare.com\n"
	m := parseRankedCSV(strings.NewReader(csv), 100)
	if m["google.com"] != 1 || m["cloudflare.com"] != 3 {
		t.Fatalf("unexpected parse result: %v", m)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 valid rows, got %d (%v)", len(m), m)
	}
}

func TestParseRankedCSV_PreservesSubdomains(t *testing.T) {
	csv := "1,edge.example.test\n2,api.eu.example.co.uk\n"
	m := parseRankedCSV(strings.NewReader(csv), 100)
	if m["edge.example.test"] != 1 || m["api.eu.example.co.uk"] != 2 {
		t.Fatalf("subdomain labels were not preserved: %v", m)
	}
}

func TestParseRankedCSV_RejectsRanksOutsideLimit(t *testing.T) {
	csv := "0,zero.example\n1,one.example\n3,three.example\n4,four.example\n"
	m := parseRankedCSV(strings.NewReader(csv), 3)
	if len(m) != 2 {
		t.Fatalf("expected two valid rows, got %d (%v)", len(m), m)
	}
	if _, ok := m["zero.example"]; ok {
		t.Fatalf("rank zero must be rejected: %v", m)
	}
	if _, ok := m["four.example"]; ok {
		t.Fatalf("rank above max must be rejected: %v", m)
	}
}

func TestRankedToSlice_OrderedByRank(t *testing.T) {
	m := map[string]int{"b.com": 2, "a.com": 1, "c.com": 3}
	got := rankedToSlice(m)
	want := []string{"a.com", "b.com", "c.com"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order mismatch at %d: got %v want %v", i, got, want)
		}
	}
}

func TestDisabledSourceDoesNotReturnTargets(t *testing.T) {
	f := NewFetcher(nil)
	r, source, listID, err := f.FetchRanked()
	if err == nil || r != nil || source != "" || listID != "" {
		t.Fatalf("disabled source returned data: ranked=%v source=%q id=%q err=%v", r, source, listID, err)
	}
}
