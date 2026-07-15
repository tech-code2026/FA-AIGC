package vss

import (
	bn128 "aigc/bn128"
	"aigc/crypto/ss"
	"crypto/rand"
	"errors"
	"math/big"
)

type PubPara struct {
	G1  *bn128.G1
	H   *bn128.G1
	Par *ss.PubPara
}

func Setup(n, t int) (*PubPara, error) {
	par, err := ss.Setup(n, t)
	if err != nil {
		return nil, err
	}
	return SetupWithPar(par)
}

func SetupWithPar(par *ss.PubPara) (*PubPara, error) {
	if par == nil {
		return nil, errors.New("nil ss parameters")
	}
	g1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	hScalar, err := rand.Int(rand.Reader, par.Order)
	if err != nil {
		return nil, err
	}
	for hScalar.Sign() == 0 {
		hScalar, err = rand.Int(rand.Reader, par.Order)
		if err != nil {
			return nil, err
		}
	}
	h := new(bn128.G1).ScalarMult(g1, hScalar)
	return &PubPara{G1: g1, H: h, Par: par}, nil
}

func PShare(pub *PubPara, s *big.Int) ([]*big.Int, []*big.Int, []*bn128.G1, error) {
	if pub == nil || pub.Par == nil || pub.G1 == nil || pub.H == nil {
		return nil, nil, nil, errors.New("invalid public parameters")
	}
	if s == nil {
		return nil, nil, nil, errors.New("secret is nil")
	}
	order := pub.Par.Order

	aCoeffs := make([]*big.Int, pub.Par.T)
	bCoeffs := make([]*big.Int, pub.Par.T)
	aCoeffs[0] = new(big.Int).Mod(new(big.Int).Set(s), order)
	for i := 1; i < pub.Par.T; i++ {
		var err error
		aCoeffs[i], err = rand.Int(rand.Reader, order)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	b0, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, nil, nil, err
	}
	bCoeffs[0] = b0
	for i := 1; i < pub.Par.T; i++ {
		bCoeffs[i], err = rand.Int(rand.Reader, order)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	shares := make([]*big.Int, pub.Par.N)
	rShares := make([]*big.Int, pub.Par.N)
	for i := 0; i < pub.Par.N; i++ {
		x := big.NewInt(int64(i + 1))
		shares[i] = ss.EvaluatePolynomial(aCoeffs, x, order)
		rShares[i] = ss.EvaluatePolynomial(bCoeffs, x, order)
	}

	commitments := make([]*bn128.G1, pub.Par.T)
	for j := 0; j < pub.Par.T; j++ {
		ga := new(bn128.G1).ScalarMult(pub.G1, aCoeffs[j])
		hb := new(bn128.G1).ScalarMult(pub.H, bCoeffs[j])
		commitments[j] = new(bn128.G1).Add(ga, hb)
	}

	return shares, rShares, commitments, nil
}

// Verify the share at index idx (0-based)
func Verify(pub *PubPara, sShare, rShare *big.Int, commitments []*bn128.G1, idx int) (bool, error) {
	if pub == nil || pub.Par == nil || pub.G1 == nil || pub.H == nil {
		return false, errors.New("invalid public parameters")
	}
	if sShare == nil || rShare == nil {
		return false, errors.New("share is nil")
	}
	if idx < 0 || idx >= pub.Par.N {
		return false, errors.New("share index out of range")
	}
	if len(commitments) != pub.Par.T {
		return false, errors.New("commitment length mismatch")
	}

	left := new(bn128.G1).Add(
		new(bn128.G1).ScalarMult(pub.G1, sShare),
		new(bn128.G1).ScalarMult(pub.H, rShare),
	)

	x := big.NewInt(int64(idx + 1))
	order := pub.Par.Order

	acc := new(bn128.G1).ScalarBaseMult(big.NewInt(0))
	pow := big.NewInt(1)
	for j := 0; j < pub.Par.T; j++ {
		term := new(bn128.G1).ScalarMult(commitments[j], pow)
		acc.Add(acc, term)
		pow.Mul(pow, x)
		pow.Mod(pow, order)
	}

	return string(left.Marshal()) == string(acc.Marshal()), nil
}

func Reconstruct(pub *PubPara, I []int, shares []*big.Int) (*big.Int, error) {
	if pub == nil || pub.Par == nil {
		return nil, errors.New("invalid public parameters")
	}
	return ss.Recon(I, shares, pub.Par)
}
