package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	// "testing"
	// "time"
	contract "aigc/compile/contract"
	"aigc/utils"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"aigc/crypto/aigc"
	// "aigc/crypto/nizk"
	"aigc/crypto/ss"

	bn128 "aigc/bn128"
	// bn128 "github.com/cloudflare/bn256"
)

func G1ToPoint(point *bn128.G1) contract.VerificationG1Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	g1Point := contract.VerificationG1Point{
		X: x,
		Y: y,
	}
	return g1Point
}

func G1sToPoints(par *aigc.GPar, points []*bn128.G1) []contract.VerificationG1Point {
	g1Points := make([]contract.VerificationG1Point, par.Par.N)
	for i := 0; i < len(points); i++ {
		g1Points[i] = G1ToPoint(points[i])
	}
	return g1Points
}

func G1sToPointsT(t int, points []*bn128.G1) []contract.VerificationG1Point {
	g1Points := make([]contract.VerificationG1Point, t)
	for i := 0; i < len(points); i++ {
		g1Points[i] = G1ToPoint(points[i])
	}
	return g1Points
}

func G2ToPoint(point *bn128.G2) contract.VerificationG2Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())

	// Create big.Int for X and Y coordinates
	a1 := new(big.Int).SetBytes(pointBytes[:32])
	a2 := new(big.Int).SetBytes(pointBytes[32:64])
	b1 := new(big.Int).SetBytes(pointBytes[64:96])
	b2 := new(big.Int).SetBytes(pointBytes[96:128])

	g2Point := contract.VerificationG2Point{
		X: [2]*big.Int{a1, a2},
		Y: [2]*big.Int{b1, b2},
	}
	return g2Point
}

func G2sToPoints(par *aigc.GPar, points []*bn128.G2) []contract.VerificationG2Point {
	g2Points := make([]contract.VerificationG2Point, par.Par.N)
	for i := 0; i < len(points); i++ {
		g2Points[i] = G2ToPoint(points[i])
	}
	return g2Points
}

func intTobigInt(par *aigc.GPar, I []int) []*big.Int {
	bigI := make([]*big.Int, par.Par.T)
	for i := 0; i < len(I); i++ {
		bigI[i] = big.NewInt(int64(I[i]))
	}
	return bigI
}

func main() {
	// ========== Global System Initialization ==========

	// g1 := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	// g2 := new(bn128.G2).ScalarBaseMult(big.NewInt(1))
	// g1p := new(bn128p.G1).ScalarBaseMult(big.NewInt(1))
	// g2p := new(bn128p.G2).ScalarBaseMult(big.NewInt(1))
	// fmt.Printf("bn128 g1 =  ", g1)
	// fmt.Printf("bn128p g1 = ", g1p)
	// fmt.Printf("bn128 g2 =  ", g2)
	// fmt.Printf("bn128p g2 = ", g2p)

	contract_name := "Verification"
	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey := utils.GetENV("PRIVATE_KEY_1")

	deployTX := utils.Transact(client, privatekey, big.NewInt(0))
	if deployTX == nil {
		log.Fatalf("Failed to create transaction")
	}
	address, _ := utils.Deploy(client, contract_name, deployTX)
	if err != nil {
		log.Fatalf("Failed to deploy contract: %v\n", err)
	}
	// Create a contract instance
	ctc, _ := contract.NewContract(common.HexToAddress(address.Hex()), client)
	//======================================================================

	//======================================================================

	fmt.Printf("========== Global System Initialization ==========\n")

	f := 4
	threshold := f + 1
	n := 2*f + 1

	I := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = i
	}

	gp, _ := aigc.GlobalSetup(n, threshold)

	// Upload global parameters to blockchain
	auth0 := utils.Transact(client, privatekey, big.NewInt(0))
	tx0, _ := ctc.UploadGPar(auth0, big.NewInt(int64(n)), big.NewInt(int64(threshold)))

	receipt0, err := bind.WaitMined(context.Background(), client, tx0)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Upload the parameters Gas used: %d\n", receipt0.GasUsed)

	cskShares, cpk, _ := aigc.DKGen(gp)

	cpk1Shares := make([]*bn128.G1, gp.Par.N)
	cpk2Shares := make([]*bn128.G2, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		cpk1Shares[i] = new(bn128.G1).ScalarMult(gp.G1, cskShares[i])
		cpk2Shares[i] = new(bn128.G2).ScalarMult(gp.G2, cskShares[i])
	}

	// ========== User Registration ==========

	// User's secret s
	fmt.Printf("========== User Registration ==========\n")
	s, _ := rand.Int(rand.Reader, gp.Par.Order)
	fmt.Println("Alice's secret s = ", s)

	sShares, rhoShares, commitment, _ := aigc.RegReq(gp, s)

	auth01 := utils.Transact(client, privatekey, big.NewInt(0))

	tx01, _ := ctc.UploadCommitment(auth01, G1sToPointsT(gp.Par.T, commitment))

	receipt01, err := bind.WaitMined(context.Background(), client, tx01)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Upload the commitment Gas used: %d\n", receipt01.GasUsed)

	urskShares, _ := aigc.KGenIssue(gp, cskShares, sShares, rhoShares, commitment, I)

	ursk, _ := aigc.KeyRecon(gp, urskShares, I)
	fmt.Println("User's secret key ursk = ", ursk)

	g1s := new(bn128.G1).ScalarMult(gp.G1, s)
	urskValid, _ := aigc.KeyVer(gp, cpk.Cpk1, ursk, g1s)
	fmt.Println("The result of KeyVer:", urskValid)

	// ========== AIGC Copyright Registration ==========

	fmt.Printf("========== AIGC Copyright Registration ==========\n")
	// image product
	// m := []byte("image product test")
	// generate size kB m
	size := 1
	m := make([]byte, size*1024)
	_, err = rand.Read(m)
	if err != nil {
		fmt.Println("Error generating random data:", err)
		return
	}
	sigmaShares, pkc, r, k, req, pi_req, _ := aigc.CopyReq(gp, m, cskShares)

	// =================================
	input := append(pkc.Marshal(), m...)
	// H(pkc || m)
	hashPointG1 := aigc.HashToG1(input)
	// =================================

	// online CopyReq
	auth1 := utils.Transact(client, privatekey, big.NewInt(0))
	tx1, _ := ctc.CopyReq(auth1, G1ToPoint(hashPointG1), G1ToPoint(req), G1ToPoint(pi_req.T), pi_req.S)

	receipt1, err := bind.WaitMined(auth1.Context, client, tx1)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Online CopyReq Gas used: %d\n", receipt1.GasUsed)

	onlineCopyReqRes, _ := ctc.GetCopyReqVerRes(&bind.CallOpts{})
	fmt.Printf("CopyReq Result on-chain:  %v\n", onlineCopyReqRes)

	T, err := aigc.AIGCReg(gp, sigmaShares, ursk.U2, cpk2Shares, cpk.Cpk2, r, k, m, pkc, I)
	if err != nil {
		log.Printf("AIGCReg failed: %v", err)
		return
	}

	// Test compute sigma
	// ==================================

	rInv := new(big.Int).ModInverse(r, gp.Par.Order)
	sigmaSharesRInv := make([]*bn128.G1, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		sigmaSharesRInv[i] = new(bn128.G1).ScalarMult(sigmaShares[i], rInv)
	}
	sigma, _ := ss.ReconG1(I, sigmaSharesRInv, gp.Par)

	// ==================================

	// online AIGCReg
	auth2 := utils.Transact(client, privatekey, big.NewInt(0))
	tx2, _ := ctc.AIGCReg(auth2, G1sToPoints(gp, sigmaShares), G2sToPoints(gp, cpk2Shares), G2ToPoint(cpk.Cpk2), G1ToPoint(req), G1ToPoint(sigma), G1ToPoint(hashPointG1))

	receipt2, err := bind.WaitMined(auth2.Context, client, tx2)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Online AIGCReg Gas used: %d\n", receipt2.GasUsed)

	AIGCRegVerRes, _ := ctc.GetAIGCRegVerRes(&bind.CallOpts{})

	fmt.Println("AIGCRegVer Result on-chain = ", AIGCRegVerRes)

	// ========== AIGC Copyright Forensics ==========
	fmt.Printf("========== AIGC Copyright Forensics ==========\n")
	pi, pip, Req2, pi_req2, K, _ := aigc.AIGCReq(gp, T, m, pkc, cskShares, sShares, rhoShares, cpk1Shares, cpk2Shares, I, commitment)

	g2k := new(bn128.G2).ScalarMult(gp.G2, k)
	forenValid, _ := aigc.AIGCForen(gp, pi, pip, g2k)
	fmt.Println("The result of AIGCForen:", forenValid)

	// online AIGCReq
	auth20 := utils.Transact(client, privatekey, big.NewInt(0))
	tx20, _ := ctc.AIGCReq(auth20, G1ToPoint(hashPointG1), G1ToPoint(Req2), G1ToPoint(pi_req2.T), pi_req2.S, G2sToPoints(gp, cpk2Shares), G1sToPoints(gp, K))

	receipt20, err := bind.WaitMined(auth20.Context, client, tx20)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Online AIGCReq Gas used: %d\n", receipt20.GasUsed)

	onlineAIGCReqRes, _ := ctc.GetAIGCReqVerRes(&bind.CallOpts{})
	fmt.Printf("AIGCReq Result on-chain:  %v\n", onlineAIGCReqRes)

	// online AIGCForen
	csk, _ := ss.Recon(I, cskShares, gp.Par)

	exp := new(big.Int).Add(csk, s)
	auth3 := utils.Transact(client, privatekey, big.NewInt(0))
	tx3, _ := ctc.AIGCForen(auth3, G1ToPoint(pip), G1ToPoint(sigma), G2ToPoint(ursk.U2), exp)

	receipt3, err := bind.WaitMined(auth3.Context, client, tx3)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Online AIGCForen Gas used: %d\n", receipt3.GasUsed)

	AIGCForenRes, _ := ctc.GetAIGCForen(&bind.CallOpts{})
	fmt.Println("AIGCForen Result on-chain = ", AIGCForenRes)

	// aigc.BatchAIGCForen()
	fmt.Printf("========== Transfer ==========\n")
	nta, pkc2, reqp, pi_reqp, r2, k2, _ := aigc.TransInit(gp, m, pkc, commitment[0])

	// Upload nta, reqp, commitment[0] to blockchain
	auth31 := utils.Transact(client, privatekey, big.NewInt(0))
	tx31, _ := ctc.UploadTransfer(auth31, G1ToPoint(nta), G1ToPoint(reqp), G1ToPoint(commitment[0]))
	receipt31, err := bind.WaitMined(auth31.Context, client, tx31)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Upload the Transfer Gas used: %d\n", receipt31.GasUsed)

	inputp := append(pkc2.Marshal(), m...)
	// H(pkc || m)
	hashPointG1p := aigc.HashToG1(inputp)

	T, _, _, valid, _ := aigc.TransProof(gp, m, k, k2, r2, nta, g2k, pkc2, reqp, hashPointG1p, ursk.U2, cpk.Cpk2, cpk2Shares, cskShares, pi_reqp, commitment, I)

	fmt.Printf("The Verify result of Transfer: %v\n", valid)
	// Verify the proof on-chain

	// // Upload the proof to blockchain
	// auth32 := utils.Transact(client, privatekey, big.NewInt(0))
	// tx32, _ := ctc.UploadProof(auth32, G1ToPoint(pi_A.RG), G2ToPoint(pi_A.RH), pi_A.C, pi_A.Z)

	// receipt32, err := bind.WaitMined(auth32.Context, client, tx32)
	// if err != nil {
	// 	log.Fatalf("Tx receipt failedd: %v", err)
	// }
	// fmt.Printf("Upload the proof Gas used: %d\n", receipt32.GasUsed)

	// // Verify Transfer on chain
	// auth33 := utils.Transact(client, privatekey, big.NewInt(0))
	// tx33, _ := ctc.VerifyTransfer(auth33, G1ToPoint(hashPointG1p), G1ToPoint(pi_reqp.T), pi_reqp.S, G1ToPoint(ntak), G2ToPoint(g2k))
	// receipt33, err := bind.WaitMined(auth33.Context, client, tx33)
	// if err != nil {
	// 	log.Fatalf("Tx receipt failedd: %v", err)
	// }
	// fmt.Printf("Verify Transfer on-chain Gas used: %d\n", receipt33.GasUsed)

	// VerifyTransferRes, _ := ctc.GetTransferVerRes(&bind.CallOpts{})
	// fmt.Println("Verify TransferVerify Result on-chain = ", VerifyTransferRes)

	// ========== Trace ==========
	fmt.Printf("========== Trace ==========\n")
	sx, piShares := aigc.Trace(gp, cpk.Cpk1, sShares, I)

	// online Trace
	auth4 := utils.Transact(client, privatekey, big.NewInt(0))
	tx4, _ := ctc.Trace(auth4, G1ToPoint(cpk.Cpk1), sShares, intTobigInt(gp, I))

	receipt4, err := bind.WaitMined(auth4.Context, client, tx4)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Online Trace Gas used: %d\n", receipt4.GasUsed)

	traceValid, _ := aigc.TraceVer(gp, piShares, cpk.Cpk1, sx, I)
	fmt.Println("The result of TraceVer", traceValid)

	// onChain TraceVer
	auth5 := utils.Transact(client, privatekey, big.NewInt(0))
	tx5, _ := ctc.TraceVer(auth5, G1sToPoints(gp, piShares), sx, G1ToPoint(cpk.Cpk1), intTobigInt(gp, I))

	receipt5, err := bind.WaitMined(auth5.Context, client, tx5)
	if err != nil {
		log.Fatalf("Tx receipt failedd: %v", err)
	}
	fmt.Printf("Online TraceVer Gas used: %d\n", receipt5.GasUsed)

	TraceVerRes, _ := ctc.GetTraceVerRes(&bind.CallOpts{})
	fmt.Println("TraceVer Result on-chain = ", TraceVerRes)
}
