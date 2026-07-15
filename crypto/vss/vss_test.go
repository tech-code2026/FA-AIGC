package vss_test

import (
	"aigc/crypto/vss"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestVSSShareVerifyRecon(t *testing.T) {
	n := 5
	threshold := 3

	pub, err := vss.Setup(n, threshold)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	s, err := rand.Int(rand.Reader, pub.Par.Order)
	if err != nil {
		t.Fatalf("rand.Int failed: %v", err)
	}

	shares, rShares, commitments, err := vss.PShare(pub, s)
	if err != nil {
		t.Fatalf("PShare failed: %v", err)
	}
	if len(shares) != n || len(rShares) != n || len(commitments) != threshold {
		t.Fatalf("unexpected output sizes: shares=%d rShares=%d commitments=%d", len(shares), len(rShares), len(commitments))
	}

	for i := 0; i < n; i++ {
		ok, err := vss.Verify(pub, shares[i], rShares[i], commitments, i)
		if err != nil {
			t.Fatalf("Verify failed: %v", err)
		}
		if !ok {
			t.Fatalf("Verify returned false at index %d", i)
		}
	}

	I := []int{0, 1, 2}
	rec, err := vss.Reconstruct(pub, I, shares)
	if err != nil {
		t.Fatalf("Reconstruct failed: %v", err)
	}
	if rec.Cmp(new(big.Int).Mod(s, pub.Par.Order)) != 0 {
		t.Fatalf("reconstructed secret mismatch")
	}

	badShare := new(big.Int).Add(shares[0], big.NewInt(1))
	badShare.Mod(badShare, pub.Par.Order)
	ok, err := vss.Verify(pub, badShare, rShares[0], commitments, 0)
	if err != nil {
		t.Fatalf("Verify failed on tampered share: %v", err)
	}
	if ok {
		t.Fatal("Verify should fail for tampered share")
	}
}
