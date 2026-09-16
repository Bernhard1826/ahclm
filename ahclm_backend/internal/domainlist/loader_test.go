package domainlist

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"ahclm/internal/models"
)

func TestNormalizeDomain(t *testing.T) {
	tests := map[string]struct {
		raw  string
		want string
		ok   bool
	}{
		"plain":     {"Example.COM", "example.com", true},
		"www":       {"www.Example.COM.", "example.com", true},
		"url":       {"https://www.example.com/path", "example.com", true},
		"comment":   {"# example.com", "", false},
		"ip":        {"192.0.2.1", "", false},
		"port":      {"example.com:443", "", false},
		"bad label": {"-example.com", "", false},
		"path":      {"example.com/path", "", false},
		"unicode":   {"例子.测试", "", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := NormalizeDomain(tt.raw)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("NormalizeDomain(%q) = (%q, %v), want (%q, %v)", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestLoadSourceLinesAndJSONL(t *testing.T) {
	dir := t.TempDir()
	linesPath := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(linesPath, []byte("\ufeffExample.COM\nwww.example.com\n# ignored\n192.0.2.1\nsecond.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSource(context.Background(), models.LocalListSourceConfig{Name: "lines", Path: linesPath, Format: "lines"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"example.com", "second.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %#v, want %#v", got, want)
	}

	jsonlPath := filepath.Join(dir, "domains.jsonl")
	contents := "{\"domain\":\"one.example\",\"url\":\"https://www.two.example/a\",\"domains\":[\"three.example\"]}\nnot-json\n{\"domain\":\"one.example\"}\n"
	if err := os.WriteFile(jsonlPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = LoadSource(context.Background(), models.LocalListSourceConfig{Name: "jsonl", Path: jsonlPath, Format: "jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"one.example", "three.example", "two.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("jsonl = %#v, want %#v", got, want)
	}
}

func TestLoadSourcesAndMaxDomains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(path, []byte("a.example\nb.example\na.example\nc.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSource(context.Background(), models.LocalListSourceConfig{Path: path, Format: "lines", MaxDomains: 2})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.example", "b.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("limited source = %#v, want %#v", got, want)
	}
	combined, err := LoadSources(context.Background(), []models.LocalListSourceConfig{{Name: "one", Path: path, Format: "lines", MaxDomains: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(combined, got) {
		t.Fatalf("combined = %#v, source = %#v", combined, got)
	}
}
