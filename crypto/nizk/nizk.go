package nizk

import (
	bn128 "aigc/bn128"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

type Proof struct {
	T *bn128.GT // commitment
	S *big.Int  // response
}

func hashToChallenge(g, y, t *bn128.GT) *big.Int {
	h := sha256.New()
	h.Write(g.Marshal())
	h.Write(y.Marshal())
	h.Write(t.Marshal())
	c := new(big.Int).SetBytes(h.Sum(nil))
	return c.Mod(c, bn128.Order)
}

func Prove(g, y *bn128.GT, x *big.Int) (*Proof, error) {
	q := bn128.Order
	r, _ := rand.Int(rand.Reader, q)
	t := new(bn128.GT).ScalarMult(g, r)

	c := hashToChallenge(g, y, t)
	s := new(big.Int).Mul(c, x)
	s.Add(s, r)
	s.Mod(s, q)

	return &Proof{T: t, S: s}, nil
}

func Verify(g, y *bn128.GT, proof *Proof) bool {
	c := hashToChallenge(g, y, proof.T)

	left := new(bn128.GT).ScalarMult(g, proof.S)
	right1 := new(bn128.GT).ScalarMult(y, c)
	right := new(bn128.GT).Add(proof.T, right1)

	return left.String() == right.String()
}

type Proofg1 struct {
	T *bn128.G1 // commitment
	S *big.Int  // response
}

func HashToChallengeG1(g, y, t *bn128.G1) *big.Int {
	h := sha256.New()
	h.Write(g.Marshal())
	h.Write(y.Marshal())
	h.Write(t.Marshal())
	c := new(big.Int).SetBytes(h.Sum(nil))
	return c.Mod(c, bn128.Order)
}

func ProveG1(g, y *bn128.G1, x *big.Int) (*Proofg1, error) {
	q := bn128.Order
	r, _ := rand.Int(rand.Reader, q)
	t := new(bn128.G1).ScalarMult(g, r)

	c := HashToChallengeG1(g, y, t)
	s := new(big.Int).Mul(c, x)
	s.Add(s, r)
	s.Mod(s, q)

	return &Proofg1{T: t, S: s}, nil
}

func VerifyG1(g, y *bn128.G1, proof *Proofg1) bool {
	c := HashToChallengeG1(g, y, proof.T)

	left := new(bn128.G1).ScalarMult(g, proof.S)
	right1 := new(bn128.G1).ScalarMult(y, c)
	right := new(bn128.G1).Add(proof.T, right1)

	return left.String() == right.String()
}

// ===========DLEQ===============================

// NIZK{x; xG = xG' and xH = xH'}(G, H, xG, xH)

type DLEQProof struct {
	C  *big.Int
	Z  *big.Int
	RG *bn128.G1
	RH *bn128.G2
}

func NewDLEQProof(G *bn128.G1, H *bn128.G2, xG *bn128.G1, xH *bn128.G2, x *big.Int) (*DLEQProof, error) {
	r, err := rand.Int(rand.Reader, bn128.Order)
	if err != nil {
		return nil, err
	}
	rG := new(bn128.G1).ScalarMult(G, r)
	rH := new(bn128.G2).ScalarMult(H, r)


	new_hash := sha256.New()
	new_hash.Write(xG.Marshal())
	new_hash.Write(xH.Marshal())
	new_hash.Write(rG.Marshal())
	new_hash.Write(rH.Marshal())

	cb := new_hash.Sum(nil)
	c := new(big.Int).SetBytes(cb)
	c.Mod(c, bn128.Order)

	z := new(big.Int).Mul(c, x)
	z.Sub(r, z)
	z.Mod(z, bn128.Order)

	dleqProof := &DLEQProof{
		C:  c,
		Z:  z,
		RG: rG,
		RH: rH,
	}

	return dleqProof, nil
}

// Verify verifies the DLEQ proof
func DLEQVerify(dleqProof *DLEQProof, G *bn128.G1, H *bn128.G2, xG *bn128.G1, xH *bn128.G2) error {
	zG := new(bn128.G1).ScalarMult(G, dleqProof.Z)
	zH := new(bn128.G2).ScalarMult(H, dleqProof.Z)
	cxG := new(bn128.G1).ScalarMult(xG, dleqProof.C)
	cxH := new(bn128.G2).ScalarMult(xH, dleqProof.C)
	a := new(bn128.G1).Add(zG, cxG)
	b := new(bn128.G2).Add(zH, cxH)
	if !(dleqProof.RG.String() == a.String() && dleqProof.RH.String() == b.String()) {
		return errors.New("invalid proof")
	}
	return nil
}

// =============================================

type Req1Proof struct {
	A1 *bn128.G1
	A2 *bn128.G1
	A3 *bn128.GT
	Z1 *big.Int
	Z2 *big.Int
	Z3 *big.Int
}

func ProveReq1(g1, h *bn128.G1, req1 *bn128.GT, cpk1 *bn128.G1, commitments []*bn128.G1, v *bn128.GT, idx int, csk, s, rho *big.Int) (*Req1Proof, error) {
	if g1 == nil || h == nil || req1 == nil || cpk1 == nil || v == nil {
		return nil, errors.New("nil public input")
	}
	if csk == nil || s == nil || rho == nil {
		return nil, errors.New("nil witness")
	}
	comi, err := computeComi(commitments, idx)
	if err != nil {
		return nil, err
	}

	alpha, err := randScalar()
	if err != nil {
		return nil, err
	}
	beta, err := randScalar()
	if err != nil {
		return nil, err
	}
	gamma, err := randScalar()
	if err != nil {
		return nil, err
	}

	A1 := new(bn128.G1).ScalarMult(g1, alpha)
	A2 := new(bn128.G1).Add(
		new(bn128.G1).ScalarMult(g1, beta),
		new(bn128.G1).ScalarMult(h, gamma),
	)
	alphaBeta := new(big.Int).Add(alpha, beta)
	alphaBeta.Mod(alphaBeta, bn128.Order)
	A3 := new(bn128.GT).ScalarMult(req1, alphaBeta)

	c := hashToChallengeReq1(g1, h, req1, cpk1, comi, v, A1, A2, A3, idx)

	return &Req1Proof{
		A1: A1,
		A2: A2,
		A3: A3,
		Z1: response(c, csk, alpha),
		Z2: response(c, s, beta),
		Z3: response(c, rho, gamma),
	}, nil
}

func VerifyReq1(g1, h *bn128.G1, req1 *bn128.GT, cpk1 *bn128.G1, commitments []*bn128.G1, v *bn128.GT, idx int, proof *Req1Proof) (bool, error) {
	if g1 == nil || h == nil || req1 == nil || cpk1 == nil || v == nil || proof == nil {
		return false, errors.New("nil public input")
	}
	if proof.A1 == nil || proof.A2 == nil || proof.A3 == nil || proof.Z1 == nil || proof.Z2 == nil || proof.Z3 == nil {
		return false, errors.New("nil proof")
	}
	comi, err := computeComi(commitments, idx)
	if err != nil {
		return false, err
	}

	c := hashToChallengeReq1(g1, h, req1, cpk1, comi, v, proof.A1, proof.A2, proof.A3, idx)

	left1 := new(bn128.G1).ScalarMult(g1, proof.Z1)
	right1 := new(bn128.G1).Add(proof.A1, new(bn128.G1).ScalarMult(cpk1, c))

	left2 := new(bn128.G1).Add(
		new(bn128.G1).ScalarMult(g1, proof.Z2),
		new(bn128.G1).ScalarMult(h, proof.Z3),
	)
	right2 := new(bn128.G1).Add(proof.A2, new(bn128.G1).ScalarMult(comi, c))

	left3Exp := new(big.Int).Add(proof.Z1, proof.Z2)
	left3Exp.Mod(left3Exp, bn128.Order)
	left3 := new(bn128.GT).ScalarMult(req1, left3Exp)
	right3 := new(bn128.GT).Add(proof.A3, new(bn128.GT).ScalarMult(v, c))

	return eqG1(left1, right1) && eqG1(left2, right2) && eqGT(left3, right3), nil
}

func computeComi(commitments []*bn128.G1, idx int) (*bn128.G1, error) {
	if len(commitments) == 0 {
		return nil, errors.New("empty commitments")
	}
	if idx < 0 {
		return nil, errors.New("invalid index")
	}
	order := bn128.Order
	x := big.NewInt(int64(idx + 1))

	acc := new(bn128.G1).ScalarBaseMult(big.NewInt(0))
	pow := big.NewInt(1)
	for _, c := range commitments {
		term := new(bn128.G1).ScalarMult(c, pow)
		acc.Add(acc, term)
		pow.Mul(pow, x)
		pow.Mod(pow, order)
	}

	return acc, nil
}

func hashToChallengeReq1(g1, h *bn128.G1, req1 *bn128.GT, cpk1 *bn128.G1, comi *bn128.G1, v *bn128.GT, a1, a2 *bn128.G1, a3 *bn128.GT, idx int) *big.Int {
	hash := sha256.New()
	hash.Write(g1.Marshal())
	hash.Write(h.Marshal())
	hash.Write(req1.Marshal())
	hash.Write(cpk1.Marshal())
	hash.Write(comi.Marshal())
	hash.Write(v.Marshal())
	hash.Write(a1.Marshal())
	hash.Write(a2.Marshal())
	hash.Write(a3.Marshal())
	hash.Write(encodeIndex(idx))

	c := new(big.Int).SetBytes(hash.Sum(nil))
	return c.Mod(c, bn128.Order)
}

func encodeIndex(idx int) []byte {
	val := uint64(idx + 1)
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(val & 0xff)
		val >>= 8
	}
	return b
}

func randScalar() (*big.Int, error) {
	return rand.Int(rand.Reader, bn128.Order)
}

func response(c, x, r *big.Int) *big.Int {
	z := new(big.Int).Mul(c, x)
	z.Add(z, r)
	return z.Mod(z, bn128.Order)
}

func eqG1(a, b *bn128.G1) bool {
	return a.String() == b.String()
}

func eqGT(a, b *bn128.GT) bool {
	return a.String() == b.String()
}
