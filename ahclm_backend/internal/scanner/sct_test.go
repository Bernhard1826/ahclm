package scanner

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestParseSCTReadsLogIDAndTimestamp(t *testing.T) {
	raw := make([]byte, 43)
	raw[0] = 0
	copy(raw[1:33], bytesFromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
	binary.BigEndian.PutUint64(raw[33:41], 1_700_000_000_000)
	observation, ok := parseSCT(raw)
	if !ok {
		t.Fatal("expected a parseable SCT")
	}
	if observation.LogID != "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" {
		t.Fatalf("log id = %q", observation.LogID)
	}
	if observation.Timestamp == nil || observation.TimestampMS != 1_700_000_000_000 {
		t.Fatalf("timestamp = %#v", observation)
	}
}

func TestParseSCTListReadsLengthPrefixedEntries(t *testing.T) {
	item := make([]byte, 43)
	item[0] = 0
	copy(item[1:33], bytesFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	binary.BigEndian.PutUint64(item[33:41], 42)
	list := make([]byte, 2+2+len(item))
	binary.BigEndian.PutUint16(list[0:2], uint16(2+len(item)))
	binary.BigEndian.PutUint16(list[2:4], uint16(len(item)))
	copy(list[4:], item)
	got := parseSCTList(list)
	if len(got) != 1 || got[0].TimestampMS != 42 {
		t.Fatalf("list = %#v", got)
	}
}

func bytesFromHex(value string) []byte {
	out, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return out
}
