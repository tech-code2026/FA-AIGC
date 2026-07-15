package ss_test

import (
	"aigc/crypto/ss"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestSSS(t *testing.T) {
	n := 5         // The number of shares
	threshold := 3 // threshold

	pub, _ := ss.Setup(n, threshold)

	// Generate a random secret
	s, _ := rand.Int(rand.Reader, pub.Order)
	sp, _ := rand.Int(rand.Reader, pub.Order)

	shares, err := ss.Share(pub, s)
	if err != nil {
		t.Fatalf("Share failed: %v", err)
	}

	sharesp, err := ss.Share(pub, sp)
	if err != nil {
		t.Fatalf("Sharep failed: %v", err)
	}

	I := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = i
	}

	secret, err := ss.Recon(I, shares, pub)
	if err != nil {
		t.Fatalf("Error in Recon: %v", err)
	}
	fmt.Println("recover secret = ", secret)
	fmt.Println("orignal secret = ", s)

	if s.Cmp(secret) != 0 {
		t.Fatal("Recovered secret does not match the original secret")
	}

	// Homomorphic addition
	addRes, _ := ss.AddHomomorphic(shares, sharesp, pub)
	recAdd, _ := ss.Recon(I, addRes, pub)
	add := new(big.Int).Add(s, sp)
	add.Mod(add, pub.Order)
	fmt.Println("s1 + s2 =", add, " reconstructed:", recAdd)

	// Homomorphic multiplication
	mulRes, _ := ss.MulHomomorphic(shares, sharesp, pub)
	recMul, _ := ss.Recon(I, mulRes, pub)
	mul := new(big.Int).Mul(s, sp)
	mul.Mod(mul, pub.Order)
	fmt.Println("s1 * s2 =", mul, " reconstructed:", recMul)

}
