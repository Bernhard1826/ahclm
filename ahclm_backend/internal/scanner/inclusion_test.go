package scanner

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"ahclm/internal/models"
)

func TestMerkleInclusionVerifiesSingleLeafTree(t *testing.T) {
	leaf := sha256.Sum256([]byte("leaf"))
	hash := base64.StdEncoding.EncodeToString(leaf[:])
	if !verifyMerkleInclusion(hash, 0, 1, nil, leaf[:]) {
		t.Fatal("single-leaf tree must verify against its own hash")
	}
}

func TestMerkleInclusionVerifiesLeftChild(t *testing.T) {
	left := sha256.Sum256([]byte("left"))
	right := sha256.Sum256([]byte("right"))
	root := merkleHashNode(left[:], right[:])
	hash := base64.StdEncoding.EncodeToString(left[:])
	if !verifyMerkleInclusion(hash, 0, 2, [][]byte{right[:]}, root) {
		t.Fatal("left child must verify")
	}
	hash = base64.StdEncoding.EncodeToString(right[:])
	if !verifyMerkleInclusion(hash, 1, 2, [][]byte{left[:]}, root) {
		t.Fatal("right child must verify")
	}
}

func TestMerkleLeafHashIsStable(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	hash, ok := merkleLeafHash(ctEntryX509, 1_700_000_000_000, nil, payload, nil)
	if !ok || hash == "" {
		t.Fatalf("hash = %q", hash)
	}
	again, _ := merkleLeafHash(ctEntryX509, 1_700_000_000_000, nil, payload, nil)
	if hash != again {
		t.Fatal("leaf hash must be deterministic")
	}
}

func TestSCTParseKeepsExtensions(t *testing.T) {
	raw := make([]byte, 45)
	raw[0] = 0
	copy(raw[1:33], bytesFromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
	raw[41] = 0
	raw[42] = 2
	raw[43] = 9
	raw[44] = 8
	raw = append(raw, 4, 3, 0, 1, 0) // structurally complete; not a verified signature
	observation, ok := parseSCT(raw)
	if !ok {
		t.Fatal("expected parseable SCT")
	}
	if len(observation.Extensions) != 2 || observation.Extensions[0] != 9 {
		t.Fatalf("extensions = %#v", observation.Extensions)
	}
	_ = models.SCTInclusionUnchecked
}
