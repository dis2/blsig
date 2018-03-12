package blsig

import (
	"testing"
)

func TestSigVerify(t *testing.T) {
	sk := GenPrivKey([]byte("seed"))
	pk := sk.Public()
	msg := []byte("hello")
	sig := sk.Sign(msg)
	ok1 := Verify(msg, pk, sig)

	sk2 := GenPrivKey([]byte("seed2"))
	pk2 := sk2.Public()
	msg2 := []byte("hello2")
	sig2 := sk2.Sign(msg2)
	ok2 := Verify(msg2, pk2, sig2)

	agg := Aggregate([][]byte{sig,sig2})
	aggok := VerifyAggregate([][]byte{msg,msg2}, [][]byte{pk,pk2}, agg, true)

	if !ok1 {
		t.Fatal("sig1 failed")
	}
	if !ok2 {
		t.Fatal("sig2 failed")
	}
	if !aggok {
		t.Fatal("aggregate signature failed")
	}
}

