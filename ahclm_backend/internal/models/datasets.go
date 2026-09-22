package models

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"strings"
	"sync"
)

// Public evidence datasets used to name operators and CT logs. Builtin
// prefixes remain a fallback; live official lists replace them when loaded.

type DatasetPrefix struct {
	Network *net.IPNet
	Vendor  string
	Source  string
}

type DatasetLog struct {
	LogID        string
	URL          string
	Operator     string
	State        string
	Key          string
	Qualified    bool
	ChromeListed bool
	AppleListed  bool
}

type DatasetSnapshot struct {
	Prefixes []DatasetPrefix
	Logs     map[string]DatasetLog
}

const (
	DirectoryAgreementNone     = ""
	DirectoryAgreementAgreed   = "agreed"
	DirectoryAgreementSingle   = "single_source"
	DirectoryAgreementConflict = "conflict"
)

var (
	datasetMu       sync.RWMutex
	datasetSnapshot DatasetSnapshot
)

func ReplaceEvidenceDatasets(snapshot DatasetSnapshot) {
	datasetMu.Lock()
	defer datasetMu.Unlock()
	datasetSnapshot = snapshot
}

func CurrentEvidenceDatasets() DatasetSnapshot {
	datasetMu.RLock()
	defer datasetMu.RUnlock()
	return datasetSnapshot
}

func DatasetPrefixCount() int {
	datasetMu.RLock()
	defer datasetMu.RUnlock()
	return len(datasetSnapshot.Prefixes)
}

func DatasetLogCount() int {
	datasetMu.RLock()
	defer datasetMu.RUnlock()
	return len(datasetSnapshot.Logs)
}

func DatasetLogListCount(list string) int {
	list = strings.ToLower(strings.TrimSpace(list))
	datasetMu.RLock()
	defer datasetMu.RUnlock()
	count := 0
	for _, entry := range datasetSnapshot.Logs {
		switch list {
		case "chrome":
			if entry.ChromeListed {
				count++
			}
		case "apple":
			if entry.AppleListed {
				count++
			}
		}
	}
	return count
}

func DatasetVendorFromAddress(address string) (vendor, source string) {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return CDNVendorNone, ""
	}
	datasetMu.RLock()
	defer datasetMu.RUnlock()
	bestBits := -1
	conflict := false
	for _, prefix := range datasetSnapshot.Prefixes {
		if prefix.Network == nil || !prefix.Network.Contains(ip) {
			continue
		}
		ones, _ := prefix.Network.Mask.Size()
		if ones > bestBits {
			bestBits = ones
			vendor = prefix.Vendor
			source = prefix.Source
			conflict = false
			continue
		}
		if ones == bestBits && prefix.Vendor != vendor {
			conflict = true
		}
	}
	if conflict {
		return CDNVendorNone, "official_prefix_conflict"
	}
	if vendor == "" {
		return CDNVendorNone, ""
	}
	return vendor, source
}

func DatasetLogByID(logID string) (DatasetLog, bool) {
	logID = NormalizeCTLogID(logID)
	if logID == "" {
		return DatasetLog{}, false
	}
	datasetMu.RLock()
	defer datasetMu.RUnlock()
	entry, ok := datasetSnapshot.Logs[logID]
	return entry, ok
}

func MergeDatasetLogs(dst map[string]DatasetLog, incoming map[string]DatasetLog) map[string]DatasetLog {
	if dst == nil {
		dst = make(map[string]DatasetLog)
	}
	for id, next := range incoming {
		if id == "" {
			continue
		}
		existing, ok := dst[id]
		if !ok {
			dst[id] = next
			continue
		}
		if existing.URL == "" {
			existing.URL = next.URL
		}
		if existing.Operator == "" {
			existing.Operator = next.Operator
		}
		if existing.Key == "" {
			existing.Key = next.Key
		}
		if next.ChromeListed {
			existing.State = next.State
			existing.Qualified = next.Qualified
			if existing.URL == "" {
				existing.URL = next.URL
			}
			if existing.Operator == "" {
				existing.Operator = next.Operator
			}
		}
		existing.ChromeListed = existing.ChromeListed || next.ChromeListed
		existing.AppleListed = existing.AppleListed || next.AppleListed
		if !existing.ChromeListed {
			existing.Qualified = existing.Qualified || next.Qualified
			if existing.State == "" {
				existing.State = next.State
			}
		}
		dst[id] = existing
	}
	return dst
}

func NormalizeCTLogID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == 32 {
		return hex.EncodeToString(decoded)
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) == 32 {
		return hex.EncodeToString(decoded)
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil && len(decoded) == 32 {
		return hex.EncodeToString(decoded)
	}
	return strings.ToLower(value)
}
