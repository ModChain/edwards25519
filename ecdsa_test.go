// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package edwards25519

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"
)

func randPrivScalarKeyList(i int) []*PrivateKey {
	r := rand.New(rand.NewSource(54321))

	curve := Edwards()
	privKeyList := make([]*PrivateKey, i)
	for j := 0; j < i; j++ {
		for {
			bIn := new([32]byte)
			for k := 0; k < PrivScalarSize; k++ {
				randByte := r.Intn(255)
				bIn[k] = uint8(randByte)
			}

			bInBig := new(big.Int).SetBytes(bIn[:])
			bInBig.Mod(bInBig, curve.N)
			bIn = copyBytes(bInBig.Bytes())
			bIn[31] &= 248

			pks, _, err := PrivKeyFromScalar(bIn[:])
			if err != nil {
				r.Seed(int64(j) + r.Int63n(12345))
				continue
			}

			// No duplicates allowed.
			if j > 0 &&
				(bytes.Equal(pks.Serialize(), privKeyList[j-1].Serialize())) {
				continue
			}

			privKeyList[j] = pks
			r.Seed(int64(j) + 54321)
			break
		}
	}

	return privKeyList
}

func TestNonStandardSignatures(t *testing.T) {
	tRand := rand.New(rand.NewSource(54321))

	msg := []byte{
		0xbe, 0x13, 0xae, 0xf4,
		0xe8, 0xa2, 0x00, 0xb6,
		0x45, 0x81, 0xc4, 0xd1,
		0x0c, 0xf4, 0x1b, 0x5b,
		0xe1, 0xd1, 0x81, 0xa7,
		0xd3, 0xdc, 0x37, 0x55,
		0x58, 0xc1, 0xbd, 0xa2,
		0x98, 0x2b, 0xd9, 0xfb,
	}

	pks := randPrivScalarKeyList(50)
	for _, pk := range pks {
		r, s, err := SignRS(pk, msg)
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}

		pubX, pubY := pk.Public()
		pub := NewPublicKey(pubX, pubY)
		ok := VerifyRS(pub, msg, r, s)
		if !ok {
			t.Fatalf("expected %v, got %v", true, ok)
		}

		// Test serializing/deserializing.
		privKeyDupTest, _, err := PrivKeyFromScalar(
			copyBytes(pk.ecPk.D.Bytes())[:])

		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}

		cmp := privKeyDupTest.GetD().Cmp(pk.GetD()) == 0
		if !cmp {
			t.Fatalf("expected %v, got %v", true, cmp)
		}

		privKeyDupTest2, _, err := PrivKeyFromScalar(pk.Serialize())
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}

		cmp = privKeyDupTest2.GetD().Cmp(pk.GetD()) == 0
		if !cmp {
			t.Fatalf("expected %v, got %v", true, cmp)
		}

		// Screw up a random bit in the signature and
		// make sure it still fails.
		sig := NewSignature(r, s)
		sigBad := sig.Serialize()
		pos := tRand.Intn(63)
		bitPos := tRand.Intn(7)
		sigBad[pos] ^= 1 << uint8(bitPos)

		bSig, err := ParseSignature(sigBad)
		if err != nil {
			// Signature failed to parse, continue.
			continue
		}
		ok = VerifyRS(pub, msg, bSig.GetR(), bSig.GetS())
		if ok {
			t.Fatalf("expected %v, got %v", false, ok)
		}

		// Screw up a random bit in the pubkey and
		// make sure it still fails.
		pkBad := pub.Serialize()
		pos = tRand.Intn(31)
		if pos == 0 {
			// 0th bit in first byte doesn't matter
			bitPos = tRand.Intn(6) + 1
		} else {
			bitPos = tRand.Intn(7)
		}
		pkBad[pos] ^= 1 << uint8(bitPos)
		bPub, err := ParsePubKey(pkBad)
		if err == nil && bPub != nil {
			ok = VerifyRS(bPub, msg, r, s)
			if ok {
				t.Fatalf("expected %v, got %v", false, ok)
			}
		}

		// Append an extra byte and make sure the parse fails.
		pkBad2 := append(pub.Serialize(), 0x01)
		_, err = ParsePubKey(pkBad2)
		if err == nil {
			t.Fatal("expected err, got nil")
		}

		// Remove a random byte and make sure the parse fails.
		pkBad3 := pub.Serialize()
		pkBad3 = append(pkBad3[:pos], pkBad3[pos+1:]...)
		_, err = ParsePubKey(pkBad3)
		if err == nil {
			t.Fatal("expected err, got nil")
		}
	}
}

func randPrivKeyList(i int) []*PrivateKey {
	r := rand.New(rand.NewSource(54321))

	privKeyList := make([]*PrivateKey, i)
	for j := 0; j < i; j++ {
		for {
			bIn := new([32]byte)
			for k := 0; k < fieldIntSize; k++ {
				randByte := r.Intn(255)
				bIn[k] = uint8(randByte)
			}

			pks, _ := PrivKeyFromSecret(bIn[:])
			if pks == nil {
				continue
			}
			if j > 0 &&
				(bytes.Equal(pks.Serialize(), privKeyList[j-1].Serialize())) {
				r.Seed(int64(j) + r.Int63n(12345))
				continue
			}

			privKeyList[j] = pks
			r.Seed(int64(j) + 54321)
			break
		}
	}

	return privKeyList
}

func benchmarkSigning(b *testing.B) {
	r := rand.New(rand.NewSource(54321))
	msg := []byte{
		0xbe, 0x13, 0xae, 0xf4,
		0xe8, 0xa2, 0x00, 0xb6,
		0x45, 0x81, 0xc4, 0xd1,
		0x0c, 0xf4, 0x1b, 0x5b,
		0xe1, 0xd1, 0x81, 0xa7,
		0xd3, 0xdc, 0x37, 0x55,
		0x58, 0xc1, 0xbd, 0xa2,
		0x98, 0x2b, 0xd9, 0xfb,
	}

	numKeys := 1024
	privKeyList := randPrivKeyList(numKeys)

	for n := 0; n < b.N; n++ {
		randIndex := r.Intn(numKeys - 1)
		_, _, err := SignRS(privKeyList[randIndex], msg)
		if err != nil {
			panic("sign failure")
		}
	}
}

func BenchmarkSigningRS(b *testing.B) { benchmarkSigning(b) }

func benchmarkSigningNonStandard(b *testing.B) {
	r := rand.New(rand.NewSource(54321))
	msg := []byte{
		0xbe, 0x13, 0xae, 0xf4,
		0xe8, 0xa2, 0x00, 0xb6,
		0x45, 0x81, 0xc4, 0xd1,
		0x0c, 0xf4, 0x1b, 0x5b,
		0xe1, 0xd1, 0x81, 0xa7,
		0xd3, 0xdc, 0x37, 0x55,
		0x58, 0xc1, 0xbd, 0xa2,
		0x98, 0x2b, 0xd9, 0xfb,
	}

	numKeys := 250
	privKeyList := randPrivScalarKeyList(numKeys)

	for n := 0; n < b.N; n++ {
		randIndex := r.Intn(numKeys - 1)
		_, _, err := SignRS(privKeyList[randIndex], msg)
		if err != nil {
			panic("sign failure")
		}
	}
}

func BenchmarkSigningNonStandard(b *testing.B) { benchmarkSigningNonStandard(b) }

type SignatureVerParams struct {
	pubkey *PublicKey
	msg    []byte
	sig    *Signature
}

func randSigList(i int) []*SignatureVerParams {
	r := rand.New(rand.NewSource(54321))

	privKeyList := make([]*PrivateKey, i)
	for j := 0; j < i; j++ {
		for {
			bIn := new([32]byte)
			for k := 0; k < fieldIntSize; k++ {
				randByte := r.Intn(255)
				bIn[k] = uint8(randByte)
			}

			pks, _ := PrivKeyFromSecret(bIn[:])
			if pks == nil {
				continue
			}
			privKeyList[j] = pks
			r.Seed(int64(j) + 54321)
			break
		}
	}

	msgList := make([][]byte, i)
	for j := 0; j < i; j++ {
		m := make([]byte, 32)
		for k := 0; k < fieldIntSize; k++ {
			randByte := r.Intn(255)
			m[k] = uint8(randByte)
		}
		msgList[j] = m
		r.Seed(int64(j) + 54321)
	}

	sigsList := make([]*Signature, i)
	for j := 0; j < i; j++ {
		r, s, err := SignRS(privKeyList[j], msgList[j])
		if err != nil {
			panic("sign failure")
		}
		sig := &Signature{r, s}
		sigsList[j] = sig
	}

	sigStructList := make([]*SignatureVerParams, i)
	for j := 0; j < i; j++ {
		ss := new(SignatureVerParams)
		pkx, pky := privKeyList[j].Public()
		ss.pubkey = NewPublicKey(pkx, pky)
		ss.msg = msgList[j]
		ss.sig = sigsList[j]
		sigStructList[j] = ss
	}

	return sigStructList
}

func benchmarkVerification(b *testing.B) {
	r := rand.New(rand.NewSource(54321))

	numSigs := 1024
	sigList := randSigList(numSigs)

	for n := 0; n < b.N; n++ {
		randIndex := r.Intn(numSigs - 1)
		ver := VerifyRS(sigList[randIndex].pubkey,
			sigList[randIndex].msg,
			sigList[randIndex].sig.R,
			sigList[randIndex].sig.S)
		if !ver {
			panic("made invalid sig")
		}
	}
}

func BenchmarkVerificationRS(b *testing.B) { benchmarkVerification(b) }
