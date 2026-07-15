package aigc

import (
	bn128 "aigc/bn128"
	"aigc/crypto/nizk"
	"aigc/crypto/ss"
	"aigc/crypto/vss"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"strconv"
	// bn128 "github.com/cloudflare/bn256"
)

type GPar struct {
	G1  *bn128.G1
	G2  *bn128.G2
	Par *ss.PubPara
	VSS *vss.PubPara
}

type ursk struct {
	U1 *bn128.G1
	U2 *bn128.G2
}

type cpk struct {
	Cpk1 *bn128.G1
	Cpk2 *bn128.G2
}

// Global System Initialization
func GlobalSetup(n, t int) (*GPar, error) {
	par, _ := ss.Setup(n, t) // SS's parameters
	g1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn128.G2).ScalarBaseMult(big.NewInt(1))
	vssPar, err := vss.SetupWithPar(par)
	if err != nil {
		return nil, err
	}
	GP := &GPar{
		G1:  g1,
		G2:  g2,
		Par: par,
		VSS: vssPar,
	}
	return GP, nil
}

func DKGen(gp *GPar) ([]*big.Int, *cpk, error) {
	csk, _ := rand.Int(rand.Reader, gp.Par.Order)
	cskShares, _ := ss.Share(gp.Par, csk)
	cpk := &cpk{
		Cpk1: new(bn128.G1).ScalarMult(gp.G1, csk),
		Cpk2: new(bn128.G2).ScalarMult(gp.G2, csk),
	}
	return cskShares, cpk, nil
}

// User Registration
func RegReq(gp *GPar, s *big.Int) ([]*big.Int, []*big.Int, []*bn128.G1, error) {
	sShares, rhoShares, commitment, _ := vss.PShare(gp.VSS, s)
	return sShares, rhoShares, commitment, nil
}

func KGenIssue(gp *GPar, cskShares, sShares, rhoShares []*big.Int, commitments []*bn128.G1, I []int) ([]*ursk, error) {
	// Verify shares
	for i := 0; i < gp.Par.T; i++ {
		ok, err := vss.Verify(gp.VSS, sShares[i], rhoShares[i], commitments, i)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("share verification failed at index " + strconv.Itoa(i))
		}
	}

	gamShares, _ := ss.AddHomomorphic(cskShares, sShares, gp.Par)

	// alpha
	alpha, _ := rand.Int(rand.Reader, gp.Par.Order)
	alphaShares, _ := ss.Share(gp.Par, alpha)

	// (alpha * gamma)Shares
	alphaGamShares, _ := ss.MulHomomorphic(alphaShares, gamShares, gp.Par)

	// I := make([]int, gp.Par.T)
	// for i := 0; i < gp.Par.T; i++ {
	// 	I[i] = i
	// }

	// alpha * gamma
	alphaGam, _ := ss.Recon(I, alphaGamShares, gp.Par)
	// 1/(alpha * gamma)
	alphaGamInv := new(big.Int).ModInverse(alphaGam, gp.Par.Order)
	// 1/(alpha * gamma)Shares
	alphaGamInvShares := make([]*big.Int, gp.Par.N)
	urskShares := make([]*ursk, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		alphaGamInvShares[i] = new(big.Int).Mul(alphaShares[i], alphaGamInv)
		alphaGamInvShares[i].Mod(alphaGamInvShares[i], gp.Par.Order)
		urskShares[i] = &ursk{
			U1: new(bn128.G1).ScalarMult(gp.G1, alphaGamInvShares[i]),
			U2: new(bn128.G2).ScalarMult(gp.G2, alphaGamInvShares[i]),
		}
	}
	return urskShares, nil
}

func KeyRecon(gp *GPar, urskShares []*ursk, I []int) (*ursk, error) {
	// I := make([]int, gp.Par.T)
	// for i := 0; i < gp.Par.T; i++ {
	// 	I[i] = i
	// }

	G1gamShares := make([]*bn128.G1, gp.Par.N)
	G2gamShares := make([]*bn128.G2, gp.Par.N)

	for i := 0; i < gp.Par.N; i++ {
		G1gamShares[i] = urskShares[i].U1
		G2gamShares[i] = urskShares[i].U2
	}

	g1Gam, _ := ss.ReconG1(I, G1gamShares, gp.Par)
	g2Gam, _ := ss.ReconG2(I, G2gamShares, gp.Par)

	ursk := &ursk{
		U1: g1Gam,
		U2: g2Gam,
	}
	return ursk, nil
}


func KeyVer(gp *GPar, cpk1 *bn128.G1, ursk *ursk, g1s *bn128.G1) (bool, error) {
	cpkG1s := new(bn128.G1).Add(cpk1, g1s)
	left1 := bn128.Pair(cpkG1s, ursk.U2)
	right1 := bn128.Pair(gp.G1, gp.G2)
	left2 := bn128.Pair(ursk.U1, gp.G2)
	right2 := bn128.Pair(gp.G1, ursk.U2)
	if !(left1.String() == right1.String() && left2.String() == right2.String()) {
		return false, errors.New("invalid ursk")
	}
	return true, nil
}

// AIGC Content Generation
// func AIGCGen()

// AIGC Copyright Registration
func CopyReq(gp *GPar, m []byte, cskShares []*big.Int) ([]*bn128.G1, *bn128.G2, *big.Int, *big.Int, *bn128.G1, *nizk.Proofg1, error) {
	r, _ := rand.Int(rand.Reader, gp.Par.Order)
	k, _ := rand.Int(rand.Reader, gp.Par.Order)
	pkc := new(bn128.G2).ScalarMult(gp.G2, k)
	// pkc || m
	input := append(pkc.Marshal(), m...)
	// H(pkc || m)
	hashPointG1 := HashToG1(input)
	req := new(bn128.G1).ScalarMult(hashPointG1, r)

	pi_req, _ := nizk.ProveG1(hashPointG1, req, r)

	valid := nizk.VerifyG1(hashPointG1, req, pi_req)
	if !valid {
		return nil, nil, nil, nil, nil, nil, errors.New("invalid proof for req")
	}

	sigmaShares := make([]*bn128.G1, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		sigmaShares[i] = new(bn128.G1).ScalarMult(req, cskShares[i])
	}

	return sigmaShares, pkc, r, k, req, pi_req, nil
}


func AIGCReg(gp *GPar, sigmaShares []*bn128.G1, u2 *bn128.G2, cpk2Shares []*bn128.G2, cpk2 *bn128.G2, r, k *big.Int, m []byte, pkc *bn128.G2, I []int) (*bn128.GT, error) {

	// g1s := new(bn128.G1).ScalarMult(gp.G1, s)
	// g1s || m
	input := append(pkc.Marshal(), m...)
	// H(g1s || m)
	hashPointG1 := HashToG1(input)
	req := new(bn128.G1).ScalarMult(hashPointG1, r)

	for i := 0; i < gp.Par.T; i++ {
		left := bn128.Pair(sigmaShares[i], gp.G2)
		right := bn128.Pair(req, cpk2Shares[i])
		if !(left.String() == right.String()) {
			return nil, errors.New("invalid sigmaShares")
		}
	}

	// BLS
	rInv := new(big.Int).ModInverse(r, gp.Par.Order)
	sigmaSharesRInv := make([]*bn128.G1, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		sigmaSharesRInv[i] = new(bn128.G1).ScalarMult(sigmaShares[i], rInv)
	}

	// I := make([]int, gp.Par.T)
	// for i := 0; i < gp.Par.T; i++ {
	// 	I[i] = i
	// }

	sigma, _ := ss.ReconG1(I, sigmaSharesRInv, gp.Par)

	leftp := bn128.Pair(sigma, gp.G2)
	rightp := bn128.Pair(hashPointG1, cpk2)

	if !(leftp.String() == rightp.String()) {
		return nil, errors.New("invalid sigma")
	}

	u2k := new(bn128.G2).ScalarMult(u2, k)

	T := bn128.Pair(sigma, u2k)

	return T, nil
}

func HashToG1(m []byte) *bn128.G1 {
	h := sha256.Sum256(m)
	res := new(bn128.G1).ScalarBaseMult(new(big.Int).SetBytes(h[:]))
	return res
}

// AIGC Copyright Forensics
func AIGCReq(gp *GPar, T *bn128.GT, m []byte, pkc *bn128.G2, cskShares, sShares, rhoShares []*big.Int, cpk1Shares []*bn128.G1, cpk2Shares []*bn128.G2, I []int, commitment []*bn128.G1) (*bn128.GT, *bn128.G1, *bn128.G1, *nizk.Proofg1, []*bn128.G1, error) {
	d1, _ := rand.Int(rand.Reader, gp.Par.Order)
	d2, _ := rand.Int(rand.Reader, gp.Par.Order)
	Req1 := new(bn128.GT).ScalarMult(T, d1)
	input := append(pkc.Marshal(), m...)
	hashPointG1 := HashToG1(input)
	Req2 := new(bn128.G1).ScalarMult(hashPointG1, d2)

	// ZKPOK
	pi_req2, _ := nizk.ProveG1(hashPointG1, Req2, d2)
	valid := nizk.VerifyG1(hashPointG1, Req2, pi_req2)
	if !valid {
		return nil, nil, nil, nil, nil, errors.New("invalid proof for Req2")
	}

	v := make([]*bn128.GT, gp.Par.N)
	k := make([]*bn128.G1, gp.Par.N)
	// piV := make([]*nizk.Proof, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		sum := new(big.Int).Add(cskShares[i], sShares[i])
		v[i] = new(bn128.GT).ScalarMult(Req1, sum)
		// piV[i], _ = nizk.Prove(Req1, v[i], sum)
		k[i] = new(bn128.G1).ScalarMult(Req2, cskShares[i])
	}

	// \pi_V
	pi_V := make([]*nizk.Req1Proof, gp.Par.T)
	for i := 0; i < gp.Par.T; i++ {
		pi_V[i], _ = nizk.ProveReq1(gp.G1, gp.VSS.H, Req1, cpk1Shares[i], commitment, v[i], i, cskShares[i], sShares[i], rhoShares[i])
	}

	// Verify Vi
	for i := 0; i < gp.Par.T; i++ {
		ok, _ := nizk.VerifyReq1(gp.G1, gp.VSS.H, Req1, cpk1Shares[i], commitment, v[i], i, pi_V[i])
		if !ok {
			return nil, nil, nil, nil, nil, errors.New("invalid proof for V[i] at index " + strconv.Itoa(i))
		}
	}

	// Verify Ki
	for i := 0; i < gp.Par.T; i++ {
		left := bn128.Pair(k[i], gp.G2)
		right := bn128.Pair(Req2, cpk2Shares[i])
		if !(left.String() == right.String()) {
			return nil, nil, nil, nil, nil, errors.New("invalid k[i]")
		}
	}

	invd1 := new(big.Int).ModInverse(d1, gp.Par.Order)
	invd2 := new(big.Int).ModInverse(d2, gp.Par.Order)

	vInvd1 := make([]*bn128.GT, gp.Par.N)
	kInvd2 := make([]*bn128.G1, gp.Par.N)


	for i := 0; i < gp.Par.N; i++ {
		vInvd1[i] = new(bn128.GT).ScalarMult(v[i], invd1)
		kInvd2[i] = new(bn128.G1).ScalarMult(k[i], invd2)
	}

	// I := make([]int, gp.Par.T)
	// for i := 0; i < gp.Par.T; i++ {
	// 	I[i] = i
	// }

	pi, _ := ss.ReconGT(I, vInvd1, gp.Par)
	pip, _ := ss.ReconG1(I, kInvd2, gp.Par)

	return pi, pip, Req2, pi_req2, k, nil
}

func AIGCForen(gp *GPar, pi *bn128.GT, pip *bn128.G1, g2k *bn128.G2) (bool, error) {
	left := bn128.Pair(pip, g2k)
	if !(left.String() == pi.String()) {
		return false, errors.New("invalid pi, pip")
	}
	return true, nil
}

// AIGC Copyright Transfer

func TransInit(gp *GPar, m []byte, pkc *bn128.G2, commitment0 *bn128.G1) (*bn128.G1, *bn128.G2, *bn128.G1, *nizk.Proofg1, *big.Int, *big.Int, error) {
	r2, _ := rand.Int(rand.Reader, gp.Par.Order)
	k2, _ := rand.Int(rand.Reader, gp.Par.Order)
	pkc2 := new(bn128.G2).ScalarMult(gp.G2, k2)
	input := append(pkc2.Marshal(), m...)
	hashPointG1 := HashToG1(input)
	req2 := new(bn128.G1).ScalarMult(hashPointG1, r2)

	pi_req2, _ := nizk.ProveG1(hashPointG1, req2, r2)

	input2 := append(pkc.Marshal(), commitment0.Marshal()...)
	input2 = append(input2, m...)

	nta := HashToG1(input2)

	return nta, pkc2, req2, pi_req2, r2, k2, nil
}

func TransProof(gp *GPar, m []byte, k, k2, r2 *big.Int, nta *bn128.G1, g2k *bn128.G2, pkc2 *bn128.G2, req2, hashPointG12 *bn128.G1, u22, cpk2 *bn128.G2, cpk2Shares2 []*bn128.G2, cskShares2 []*big.Int, pi_req2 *nizk.Proofg1, commitment2 []*bn128.G1, I []int) (*bn128.GT, *nizk.DLEQProof, *bn128.G1, bool, error) {

	// Verify the proof for req2
	verPiReq2 := nizk.VerifyG1(hashPointG12, req2, pi_req2)
	if !verPiReq2 {
		return nil, nil, nil, false, errors.New("invalid proof for req2")
	}

	ntak := new(bn128.G1).ScalarMult(nta, k)
	piA, _ := nizk.NewDLEQProof(nta, gp.G2, ntak, g2k, k)

	// Verify the proof for ntak
	verPiA := nizk.DLEQVerify(piA, nta, gp.G2, ntak, g2k)
	if verPiA != nil {
		return nil, nil, nil, false, errors.New("invalid proof for ntak")
	}

	// Part of CopyReq
	sigmaShares2 := make([]*bn128.G1, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		sigmaShares2[i] = new(bn128.G1).ScalarMult(req2, cskShares2[i])
	}


	T, _ := AIGCReg(gp, sigmaShares2, u22, cpk2Shares2, cpk2, r2, k2, m, pkc2, I)

	return T, piA, ntak, true, nil
}

// Trace
func Trace(gp *GPar, Cpk1 *bn128.G1, sxShares []*big.Int, I []int) (*big.Int, []*bn128.G1) {
	// I := make([]int, gp.Par.T)
	// for i := 0; i < gp.Par.T; i++ {
	// 	I[i] = i
	// }
	sx, _ := ss.Recon(I, sxShares, gp.Par)
	piShares := make([]*bn128.G1, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		piShares[i] = new(bn128.G1).ScalarMult(Cpk1, sxShares[i])
	}

	return sx, piShares
}

func TraceVer(gp *GPar, piShares []*bn128.G1, Cpk1 *bn128.G1, sx *big.Int, I []int) (bool, error) {
	left, _ := ss.ReconG1(I, piShares, gp.Par)
	right := new(bn128.G1).ScalarMult(Cpk1, sx)
	if !(left.String() == right.String()) {
		return false, errors.New("wrong s*")
	}
	return true, nil
}
