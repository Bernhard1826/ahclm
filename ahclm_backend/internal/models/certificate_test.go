package models

import (
	"testing"
	"time"
)

func TestDaysUntil(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if d := DaysUntil(now.Add(48*time.Hour), now); d != 2 {
		t.Fatalf("future days = %d, want 2", d)
	}
	if d := DaysUntil(now.Add(-48*time.Hour), now); d != -2 {
		t.Fatalf("past days = %d, want -2", d)
	}
}

func TestMilestoneLabel(t *testing.T) {
	if got := MilestoneLabel(7, true); got != "7d_before_expiry" {
		t.Fatalf("got %q", got)
	}
	if got := MilestoneLabel(3, false); got != "3d_after_expiry" {
		t.Fatalf("got %q", got)
	}
}

func TestExpirationStatus(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		delta time.Duration
		want  string
	}{
		{-time.Hour, "expired"},
		{2 * 24 * time.Hour, "critical"},
		{5 * 24 * time.Hour, "warning"},
		{20 * 24 * time.Hour, "attention"},
		{100 * 24 * time.Hour, "valid"},
	}
	for _, tc := range cases {
		if got := ExpirationStatus(now.Add(tc.delta), now); got != tc.want {
			t.Fatalf("delta %v: got %q, want %q", tc.delta, got, tc.want)
		}
	}
}

func TestGetDomain(t *testing.T) {
	cases := map[string]string{
		"https://www.Example.com/path": "example.com",
		"http://foo.bar":               "foo.bar",
		"WWW.TEST.ORG":                 "test.org",
		"plain.com":                    "plain.com",
	}
	for in, want := range cases {
		if got := GetDomain(in); got != want {
			t.Fatalf("GetDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "public", ip: "209.51.188.116", want: true},
		{name: "private", ip: "10.0.0.1", want: false},
		{name: "transparent proxy benchmark", ip: "198.18.1.158", want: false},
		{name: "documentation", ip: "2001:db8::1", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsPublicIP(test.ip); got != test.want {
				t.Fatalf("IsPublicIP(%q) = %v, want %v", test.ip, got, test.want)
			}
		})
	}
}

func TestDSN(t *testing.T) {
	d := &DatabaseConfig{Host: "localhost", Port: 15432, User: "postgres", Password: "123456", Database: "x", SSLMode: "disable"}
	got := d.DSN("ahclm")
	want := "host=localhost port=15432 user=postgres password=123456 dbname=ahclm sslmode=disable"
	if got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}
}
