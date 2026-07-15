package nizk

import (
	"crypto/rand"
	"math/big"
	"testing"

	bn128 "aigc/bn128"
	"aigc/crypto/vss"
)

func TestNIZK(t *testing.T) {
	g := new(bn128.GT).ScalarBaseMult(big.NewInt(1))
	x, _ := rand.Int(rand.Reader, bn128.Order)
	y := new(bn128.GT).ScalarMult(g, x)

	proof, err := Prove(g, y, x)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	if !Verify(g, y, proof) {
		t.Fatalf("Verify failed")
	}
}

func TestReq1NIZK(t *testing.T) {
	// Build a small VSS instance to obtain commitments and a valid share.
	pub, err := vss.Setup(5, 3)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	secret, _ := rand.Int(rand.Reader, pub.Par.Order)
	shares, rShares, commitments, err := vss.PShare(pub, secret)
	if err != nil {
		t.Fatalf("PShare failed: %v", err)
	}

	idx := 0
	csk, _ := rand.Int(rand.Reader, pub.Par.Order)
	cpk1 := new(bn128.G1).ScalarMult(pub.G1, csk)

	// req1 lives in GT; v is req1^(csk+s_i).
	gtBase := new(bn128.GT).ScalarBaseMult(big.NewInt(1))
	r, _ := rand.Int(rand.Reader, pub.Par.Order)
	req1 := new(bn128.GT).ScalarMult(gtBase, r)

	csks := new(big.Int).Add(csk, shares[idx])
	csks.Mod(csks, pub.Par.Order)
	v := new(bn128.GT).ScalarMult(req1, csks)

	proof, err := ProveReq1(pub.G1, pub.H, req1, cpk1, commitments, v, idx, csk, shares[idx], rShares[idx])
	if err != nil {
		t.Fatalf("ProveReq1 failed: %v", err)
	}

	ok, err := VerifyReq1(pub.G1, pub.H, req1, cpk1, commitments, v, idx, proof)
	if err != nil {
		t.Fatalf("VerifyReq1 failed: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyReq1 returned false")
	}

	// Negative check: tamper v to ensure verification fails.
	badV := new(bn128.GT).ScalarMult(req1, new(big.Int).Add(csks, big.NewInt(1)))
	ok, err = VerifyReq1(pub.G1, pub.H, req1, cpk1, commitments, badV, idx, proof)
	if err != nil {
		t.Fatalf("VerifyReq1 failed on tampered v: %v", err)
	}
	if ok {
		t.Fatalf("VerifyReq1 should fail on tampered v")
	}
}
