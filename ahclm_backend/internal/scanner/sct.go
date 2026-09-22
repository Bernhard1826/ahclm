package scanner

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"time"

	"ahclm/internal/models"
)

// signedCertificateTimestampListOID is the X.509 poison/precertificate SCT
// list (RFC 6962). Embedded SCTs are a second, independent source from the
// handshake TLS extension.
var signedCertificateTimestampListOID = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func parseHandshakeSCTs(raw [][]byte) []models.SCTObservation {
	out := make([]models.SCTObservation, 0, len(raw))
	for _, item := range raw {
		if observation, ok := parseSCT(item); ok {
			out = append(out, observation)
		}
	}
	return mergeSCTObservations(out)
}

func parseEmbeddedSCTs(cert *x509.Certificate) []models.SCTObservation {
	if cert == nil {
		return nil
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(signedCertificateTimestampListOID) {
			continue
		}
		return parseSCTList(ext.Value)
	}
	for _, ext := range cert.ExtraExtensions {
		if !ext.Id.Equal(signedCertificateTimestampListOID) {
			continue
		}
		return parseSCTList(ext.Value)
	}
	return nil
}

func parseSCTList(payload []byte) []models.SCTObservation {
	inner := derOctetString(payload)
	if len(inner) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(inner[:2]))
	body := inner[2:]
	if listLen > len(body) {
		listLen = len(body)
	}
	body = body[:listLen]
	out := make([]models.SCTObservation, 0, 4)
	for len(body) >= 2 {
		itemLen := int(binary.BigEndian.Uint16(body[:2]))
		body = body[2:]
		if itemLen <= 0 || itemLen > len(body) {
			break
		}
		if observation, ok := parseSCT(body[:itemLen]); ok {
			out = append(out, observation)
		}
		body = body[itemLen:]
	}
	return mergeSCTObservations(out)
}

func parseSCT(raw []byte) (models.SCTObservation, bool) {
	// RFC 6962 SCT: version(1) + log_id(32) + timestamp_ms(8) + extensions + signature.
	if len(raw) < 43 {
		return models.SCTObservation{}, false
	}
	timestampMS := binary.BigEndian.Uint64(raw[33:41])
	observed := time.UnixMilli(int64(timestampMS)).UTC()
	extLen := int(binary.BigEndian.Uint16(raw[41:43]))
	if 43+extLen > len(raw) {
		return models.SCTObservation{}, false
	}
	observation := models.SCTObservation{
		Version:     int(raw[0]),
		LogID:       hex.EncodeToString(raw[1:33]),
		TimestampMS: timestampMS,
		Timestamp:   &observed,
		Extensions:  append([]byte(nil), raw[43:43+extLen]...),
	}
	annotateSCT(&observation)
	return observation, true
}

func annotateSCT(observation *models.SCTObservation) {
	if observation == nil {
		return
	}
	entry, ok := models.DatasetLogByID(observation.LogID)
	if !ok {
		return
	}
	observation.LogID = entry.LogID
	observation.LogURL = entry.URL
	observation.Operator = entry.Operator
	observation.LogState = entry.State
	observation.Qualified = entry.Qualified && entry.ChromeListed
	observation.ChromeListed = entry.ChromeListed
	observation.AppleListed = entry.AppleListed
}

func derOctetString(payload []byte) []byte {
	if len(payload) < 2 || payload[0] != 0x04 {
		return payload
	}
	length, header := derLength(payload[1:])
	if header < 0 || 1+header+length > len(payload) {
		return payload
	}
	return payload[1+header : 1+header+length]
}

func derLength(payload []byte) (length, header int) {
	if len(payload) == 0 {
		return 0, -1
	}
	if payload[0] < 0x80 {
		return int(payload[0]), 1
	}
	size := int(payload[0] & 0x7f)
	if size == 0 || size > 3 || len(payload) < 1+size {
		return 0, -1
	}
	value := 0
	for i := 0; i < size; i++ {
		value = (value << 8) | int(payload[1+i])
	}
	return value, 1 + size
}

func mergeSCTObservations(values []models.SCTObservation) []models.SCTObservation {
	seen := make(map[string]struct{}, len(values))
	out := make([]models.SCTObservation, 0, len(values))
	for _, value := range values {
		key := value.LogID + ":" + hex.EncodeToString([]byte{byte(value.Version)}) + ":" + itoa64(value.TimestampMS)
		if _, ok := seen[key]; ok || value.LogID == "" {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func itoa64(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
