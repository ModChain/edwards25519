package edwards25519

import (
	"crypto/sha512"
	"io"
)

// GenerateKey generates a public/private key pair using randomness from rand.
func GenerateKey(rand io.Reader) (publicKey *[PublicKeySize]byte, privateKey *[PrivateKeySize]byte, err error) {
	privateKey = new([64]byte)
	publicKey = new([32]byte)
	_, err = io.ReadFull(rand, privateKey[:32])
	if err != nil {
		return nil, nil, err
	}

	h := sha512.New()
	h.Write(privateKey[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest)
	GeScalarMultBase(&A, &hBytes)
	A.ToBytes(publicKey)

	copy(privateKey[32:], publicKey[:])
	return
}
