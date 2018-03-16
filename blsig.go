// Package blsig implements BLS (short) signatures and signature aggregation
// on bilinear pairing curve BLS12-381.
package blsig // import "github.com/dis2/blsig"

import "github.com/dis2/bls12"
import "crypto/sha256"
import "crypto/rand"

// Represents a private scalar.
type PrivKey struct {
	bls12.Scalar
}

// Generate terministic private key from a private seed, or random if nil.
func GenPrivKey(seed []byte) (k *PrivKey) {
	if seed == nil {
		seed = make([]byte, 64)
		rand.Read(seed)
	}
	buf := sha256.Sum256(seed)
	// clamp to 2^254-1
	buf[0] &= 0x3f
	k = &PrivKey{}
	k.Scalar.Unmarshal(buf[:])
	return
}

// Public key from private key.
func (sk *PrivKey) Public() []byte {
	return new(bls12.G2).ScalarBaseMult(&sk.Scalar).Marshal()
}

// Verify message with a given signature and public key.
func Verify(msg, pk, sig []byte) bool {
	return VerifyAggregate([][]byte{msg}, [][]byte{pk}, sig, true)
}

// Sign message m, and return signature data.
func (sk *PrivKey) Sign(m []byte) (sig []byte) {
	return new(bls12.G1).HashToPoint(m).ScalarMult(&sk.Scalar).Marshal()
}

// Take array of signatures and aggregate those into a single signature.
func Aggregate(sigs [][]byte) (aggsig []byte) {
	var g bls12.G1
	if g.Unmarshal(sigs[0]) == nil {
		return nil
	}
	sum := g
	for _, sig := range sigs[1:] {
		ok := g.Unmarshal(sig)
		if ok == nil {
			return nil
		}
		sum.Add(&g)
	}
	return sum.Marshal()
}

// Verify array of messages, public keys and aggregate signature. Allowing
// duplicate messages has tricky security implications, do that on your own
// peril.
func VerifyAggregate(msgs [][]byte, keys [][]byte, aggsig []byte, allowdupe bool) bool {
	if len(msgs) != len(keys) {
		return false
	}
	if !allowdupe {
		dupes := map[string]bool{}
		for _, m := range msgs {
			buf := sha256.Sum256(m)
			s := string(buf[:])
			if dupes[s] {
				return false
			}
			dupes[s] = true
		}
	}
	var ag bls12.G1
	if ag.Unmarshal(aggsig) == nil {
		return false
	}
	e1 := new(bls12.GT).Pair(&ag, new(bls12.G2).SetOne())
	p1 := new(bls12.G1).HashToPoint(msgs[0])
	var p2 bls12.G2
	if p2.Unmarshal(keys[0]) == nil {
		return false
	}
	e2 := new(bls12.GT).Pair(p1, &p2)
	e3 := &bls12.GT{}
	for i, m := range msgs[1:] {
		p1.HashToPoint(m)
		if p2.Unmarshal(keys[i+1]) == nil {
			return false
		}
		e3.Pair(p1, &p2)
		e2.Add(e3)
	}
	return e1.Equal(e2)
}
