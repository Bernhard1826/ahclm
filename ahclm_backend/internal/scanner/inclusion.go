package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"ahclm/internal/models"
)

const (
	ctLeafTypeTimestamped = 0
	ctEntryX509           = 0
	ctEntryPrecert        = 1
)

func (s *Scanner) verifySCTInclusions(ctx context.Context, chain []*x509.Certificate, observations []models.SCTObservation) []models.SCTObservation {
	if s == nil || !s.config.CheckSCTInclusion || len(observations) == 0 || len(chain) == 0 || chain[0] == nil {
		return observations
	}
	out := append([]models.SCTObservation(nil), observations...)
	var wg sync.WaitGroup
	for i := range out {
		if strings.TrimSpace(out[i].LogURL) == "" {
			if out[i].Inclusion == "" {
				out[i].Inclusion = models.SCTInclusionUnchecked
			}
			continue
		}
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			included, leafIndex, treeSize, err := s.proveSCTInclusion(ctx, chain, out[index])
			if err != nil {
				out[index].Inclusion = models.SCTInclusionError
				return
			}
			if included {
				out[index].Inclusion = models.SCTInclusionProven
				out[index].LeafIndex = leafIndex
				out[index].TreeSize = treeSize
				return
			}
			out[index].Inclusion = models.SCTInclusionMissing
		}(i)
	}
	wg.Wait()
	return out
}

func (s *Scanner) proveSCTInclusion(ctx context.Context, chain []*x509.Certificate, observation models.SCTObservation) (bool, uint64, uint64, error) {
	logURL := strings.TrimRight(strings.TrimSpace(observation.LogURL), "/")
	if logURL == "" {
		return false, 0, 0, fmt.Errorf("SCT has no log URL")
	}
	sth, err := s.fetchSTH(ctx, logURL)
	if err != nil {
		return false, 0, 0, err
	}
	hashes := merkleLeafHashes(chain, observation)
	if len(hashes) == 0 {
		return false, 0, 0, fmt.Errorf("no Merkle leaf hash could be built")
	}
	for _, hash := range hashes {
		proof, err := s.fetchInclusionProof(ctx, logURL, hash, sth.TreeSize)
		if err != nil {
			continue
		}
		if verifyMerkleInclusion(hash, proof.LeafIndex, sth.TreeSize, proof.AuditPath, sth.SHA256RootHash) {
			return true, proof.LeafIndex, sth.TreeSize, nil
		}
	}
	return false, 0, sth.TreeSize, nil
}

type signedTreeHead struct {
	TreeSize       uint64
	SHA256RootHash []byte
}

type inclusionProof struct {
	LeafIndex uint64
	AuditPath [][]byte
}

func (s *Scanner) fetchSTH(ctx context.Context, logURL string) (signedTreeHead, error) {
	raw, err := s.getCTJSON(ctx, logURL+"/ct/v1/get-sth")
	if err != nil {
		return signedTreeHead{}, err
	}
	var payload struct {
		TreeSize          uint64 `json:"tree_size"`
		SHA256RootHashB64 string `json:"sha256_root_hash"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return signedTreeHead{}, err
	}
	root, err := base64.StdEncoding.DecodeString(payload.SHA256RootHashB64)
	if err != nil || len(root) != 32 {
		return signedTreeHead{}, fmt.Errorf("invalid STH root hash")
	}
	return signedTreeHead{TreeSize: payload.TreeSize, SHA256RootHash: root}, nil
}

func (s *Scanner) fetchInclusionProof(ctx context.Context, logURL, leafHash string, treeSize uint64) (inclusionProof, error) {
	endpoint := logURL + "/ct/v1/get-proof-by-hash?hash=" + url.QueryEscape(leafHash) + "&tree_size=" + fmt.Sprintf("%d", treeSize)
	raw, err := s.getCTJSON(ctx, endpoint)
	if err != nil {
		return inclusionProof{}, err
	}
	var payload struct {
		LeafIndex uint64   `json:"leaf_index"`
		AuditPath []string `json:"audit_path"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return inclusionProof{}, err
	}
	path := make([][]byte, 0, len(payload.AuditPath))
	for _, item := range payload.AuditPath {
		decoded, err := base64.StdEncoding.DecodeString(item)
		if err != nil || len(decoded) != 32 {
			return inclusionProof{}, fmt.Errorf("invalid audit path node")
		}
		path = append(path, decoded)
	}
	return inclusionProof{LeafIndex: payload.LeafIndex, AuditPath: path}, nil
}

func (s *Scanner) getCTJSON(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	ua := "AHCLM-CertMonitor/2.0"
	if s.config != nil && strings.TrimSpace(s.config.UserAgent) != "" {
		ua = s.config.UserAgent
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("%s returned HTTP %d", endpoint, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func merkleLeafHashes(chain []*x509.Certificate, observation models.SCTObservation) []string {
	if len(chain) == 0 || chain[0] == nil {
		return nil
	}
	leaf := chain[0]
	out := make([]string, 0, 2)
	if hash, ok := merkleLeafHash(ctEntryX509, observation.TimestampMS, observation.Extensions, leaf.Raw, nil); ok {
		out = append(out, hash)
	}
	if len(chain) > 1 && chain[1] != nil {
		issuerHash := sha256.Sum256(chain[1].RawSubjectPublicKeyInfo)
		tbs := stripPrecertExtensions(leaf.RawTBSCertificate)
		if hash, ok := merkleLeafHash(ctEntryPrecert, observation.TimestampMS, observation.Extensions, tbs, issuerHash[:]); ok {
			out = append(out, hash)
		}
	}
	return uniqueStrings(out)
}

func merkleLeafHash(entryType int, timestampMS uint64, extensions, payload, issuerKeyHash []byte) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}
	body := make([]byte, 0, 16+len(payload)+len(extensions)+len(issuerKeyHash))
	body = append(body, 0) // MerkleTreeLeaf version
	body = append(body, ctLeafTypeTimestamped)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], timestampMS)
	body = append(body, ts[:]...)
	body = append(body, byte(entryType))
	if entryType == ctEntryPrecert {
		if len(issuerKeyHash) != 32 {
			return "", false
		}
		body = append(body, issuerKeyHash...)
	}
	body = appendUint24(body, len(payload))
	body = append(body, payload...)
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(extensions)))
	body = append(body, extLen[:]...)
	body = append(body, extensions...)
	sum := sha256.Sum256(append([]byte{0x00}, body...))
	return base64.StdEncoding.EncodeToString(sum[:]), true
}

func appendUint24(dst []byte, value int) []byte {
	return append(dst, byte(value>>16), byte(value>>8), byte(value))
}

func verifyMerkleInclusion(leafHashB64 string, index, treeSize uint64, auditPath [][]byte, root []byte) bool {
	if treeSize == 0 || index >= treeSize || len(root) != 32 {
		return false
	}
	current, err := base64.StdEncoding.DecodeString(leafHashB64)
	if err != nil || len(current) != 32 {
		return false
	}
	fn := index
	sn := treeSize - 1
	for _, sibling := range auditPath {
		if len(sibling) != 32 {
			return false
		}
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			current = merkleHashNode(sibling, current)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			current = merkleHashNode(current, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytesEqual(current, root)
}

func merkleHashNode(left, right []byte) []byte {
	sum := sha256.Sum256(append(append([]byte{0x01}, left...), right...))
	return sum[:]
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func stripPrecertExtensions(tbs []byte) []byte {
	return tbs
}
