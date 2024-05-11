package edwards25519

import (
	"crypto/sha512"
	"crypto/subtle"
)

// Verify returns true iff sig is a valid signature of message by publicKey.
func Verify(publicKey *[PublicKeySize]byte, message []byte, sig *[SignatureSize]byte) bool {
	if sig[63]&224 != 0 {
		return false
	}

	var A ExtendedGroupElement
	if !A.FromBytes(publicKey) {
		return false
	}
	FeNeg(&A.X, &A.X)
	FeNeg(&A.T, &A.T)

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	ScReduce(&hReduced, &digest)

	var R ProjectiveGroupElement
	var b [32]byte
	copy(b[:], sig[32:])
	GeDoubleScalarMultVartime(&R, &hReduced, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return subtle.ConstantTimeCompare(sig[:32], checkR[:]) == 1
}
