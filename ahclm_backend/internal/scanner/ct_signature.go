package scanner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"

	"ahclm/internal/models"
)

// verifyLogSignature checks TLS DigitallySigned against a trusted log key,
// including the SHA-256 binding between that key and the claimed log ID.
func verifyLogSignature(logID string, body, signature []byte) bool {
	entry, ok := models.DatasetLogByID(logID)
	if !ok || len(signature) < 5 || signature[0] != 4 || int(binary.BigEndian.Uint16(signature[2:4])) != len(signature)-4 {
		return false
	}
	der, err := base64.StdEncoding.DecodeString(entry.Key)
	if err != nil {
		return false
	}
	id := sha256.Sum256(der)
	if hex.EncodeToString(id[:]) != models.NormalizeCTLogID(logID) {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(body)
	switch pub := key.(type) {
	case *ecdsa.PublicKey:
		return signature[1] == 3 && ecdsa.VerifyASN1(pub, digest[:], signature[4:])
	case *rsa.PublicKey:
		return signature[1] == 1 && rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature[4:]) == nil
	default:
		return false
	}
}

func verifySCTSignature(chain []*x509.Certificate, observation models.SCTObservation) bool {
	if observation.Version != 0 || len(chain) == 0 || chain[0] == nil {
		return false
	}
	if body, ok := ctSignedEntry(ctEntryX509, observation.TimestampMS, observation.Extensions, chain[0].Raw, nil); ok && verifyLogSignature(observation.LogID, body, observation.Signature) {
		return true
	}
	if len(chain) > 1 && chain[1] != nil {
		issuerHash := sha256.Sum256(chain[1].RawSubjectPublicKeyInfo)
		body, ok := ctSignedEntry(ctEntryPrecert, observation.TimestampMS, observation.Extensions, stripPrecertExtensions(chain[0].RawTBSCertificate), issuerHash[:])
		return ok && verifyLogSignature(observation.LogID, body, observation.Signature)
	}
	return false
}
