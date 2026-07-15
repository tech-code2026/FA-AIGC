package aigc_test

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"aigc/crypto/aigc"

	bn128 "aigc/bn128"
	// bn128 "github.com/cloudflare/bn256"
)

func TestGsStup(t *testing.T) {
	n, threshold := 5, 3
	gp, err := aigc.GlobalSetup(n, threshold)
	if err != nil {
		t.Fatalf("Error during setup: %v", err)
	}

	if gp.G1 == nil || gp.G2 == nil || gp.Par.Order == nil {
		t.Fatal("Failed to initialize group generator or group order")
	}

	if gp.Par.N != n || gp.Par.T != threshold {
		t.Fatal("Public parameters n or t do not match the input values")
	}
}

func TestAIGC(t *testing.T) {

	// ========== Global System Initialization ==========

	f := 13
	threshold := f + 1
	n := 2*f + 1

	N := 1 // The number of Users

	I := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = i
	}

	gp, _ := aigc.GlobalSetup(n, threshold)

	cskShares, cpk, _ := aigc.DKGen(gp)

	cpk1Shares := make([]*bn128.G1, gp.Par.N)
	cpk2Shares := make([]*bn128.G2, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		cpk1Shares[i] = new(bn128.G1).ScalarMult(gp.G1, cskShares[i])
		cpk2Shares[i] = new(bn128.G2).ScalarMult(gp.G2, cskShares[i])
	}

	aigc_n := 1 // The number of AIGC products

	numRuns := 100 // The number of runs for averaging time
	var totalDuration time.Duration

	// ========== User Registration ==========

	// User's secret s
	s, _ := rand.Int(rand.Reader, gp.Par.Order)
	// fmt.Println("User's secret s = ", s)

	fmt.Print("===========User Registration============\n")

	sShares, rhoShares, commitment, _ := aigc.RegReq(gp, s)
	// startTime1 := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _, _, _ = aigc.RegReq(gp, s)
	// }
	// endTime1 := time.Now()
	// totalDuration = endTime1.Sub(startTime1)

	// averageDuration1 := totalDuration / time.Duration(numRuns)

	// fmt.Printf("RegReq Time with t = %d, n = %d: %s\n", threshold, n, averageDuration1)

	urskShares, _ := aigc.KGenIssue(gp, cskShares, sShares, rhoShares, commitment, I)
	// startTime2 := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = aigc.KGenIssue(gp, cskShares, sShares, rhoShares, commitment, I)
	// }
	// endTime2 := time.Now()
	// totalDuration = endTime2.Sub(startTime2)

	// averageDuration2 := totalDuration / time.Duration(numRuns)

	// fmt.Printf("KGenIssue Time with t = %d, n = %d: %s\n", threshold, n, averageDuration2)

	ursk, _ := aigc.KeyRecon(gp, urskShares, I)
	fmt.Println("User's secret key ursk = ", ursk)
	// startTime3 := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = aigc.KeyRecon(gp, urskShares, I)
	// }
	// endTime3 := time.Now()
	// totalDuration = endTime3.Sub(startTime3)

	// averageDuration3 := totalDuration / time.Duration(numRuns)

	// fmt.Printf("KeyRecon Time with t = %d, n = %d: %s\n", threshold, n, averageDuration3)

	g1s := new(bn128.G1).ScalarMult(gp.G1, s)
	urskValid, _ := aigc.KeyVer(gp, cpk.Cpk1, ursk, g1s)
	fmt.Println("The result of KeyVer", urskValid)
	// startTime4 := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = aigc.KeyVer(gp, cpk.Cpk1, ursk, g1s)
	// }
	// endTime4 := time.Now()
	// totalDuration = endTime4.Sub(startTime4)

	// averageDuration4 := totalDuration / time.Duration(numRuns)

	// fmt.Printf("KeyVer Time with t = %d, n = %d: %s\n", threshold, n, averageDuration4)

	// fmt.Printf("User Registration total Time with t = %d, n = %d: %s\n\n", threshold, n, averageDuration1+averageDuration2+averageDuration3)

	// ========== AIGC Copyright Registration ==========

	fmt.Print("===========AIGC Copyright Registration============\n")
	// image product
	// m := []byte("image product test")
	// generate size MB m
	size := 600
	m := make([]byte, size*1024*1024)
	_, err := rand.Read(m)
	if err != nil {
		fmt.Println("Error generating random data:", err)
		return
	}
	sigmaShares, pkc, r, k, _, _, _ := aigc.CopyReq(gp, m, cskShares)
	startTime5 := time.Now()
	for i := 0; i < numRuns*aigc_n; i++ {
		_, _, _, _, _, _, _ = aigc.CopyReq(gp, m, cskShares)
	}
	endTime5 := time.Now()
	totalDuration = endTime5.Sub(startTime5)

	averageDuration5 := totalDuration / time.Duration(numRuns)

	fmt.Printf("CopyReq Time with t = %d, n = %d: %s\n", threshold, n, averageDuration5)

	T, err := aigc.AIGCReg(gp, sigmaShares, ursk.U2, cpk2Shares, cpk.Cpk2, r, k, m, pkc, I)
	if err != nil {
		fmt.Printf("Invalid sigma or sigmaShares\n")
	}
	startTime6 := time.Now()
	for i := 0; i < numRuns*aigc_n; i++ {
		_, _ = aigc.AIGCReg(gp, sigmaShares, ursk.U2, cpk2Shares, cpk.Cpk2, r, k, m, pkc, I)
	}
	endTime6 := time.Now()
	totalDuration = endTime6.Sub(startTime6)

	averageDuration6 := totalDuration / time.Duration(numRuns)

	fmt.Printf("AIGCReg Time with t = %d, n = %d: %s\n", threshold, n, averageDuration6)

	fmt.Printf("AIGC Registration total Time with t = %d, n = %d, agic_n = %d, aigc_size = %d: %s\n\n", threshold, n, aigc_n, size, averageDuration5+averageDuration6)

	// ========== AIGC Copyright Forensics ==========
	fmt.Print("===========AIGC Copyright Forensic============\n")
	pi, pip, _, _, _, _ := aigc.AIGCReq(gp, T, m, pkc, cskShares, sShares, rhoShares, cpk1Shares, cpk2Shares, I, commitment)
	startTime7 := time.Now()
	for i := 0; i < numRuns*aigc_n; i++ {
		_, _, _, _, _, _ = aigc.AIGCReq(gp, T, m, pkc, cskShares, sShares, rhoShares, cpk1Shares, cpk2Shares, I, commitment)
	}
	endTime7 := time.Now()
	totalDuration = endTime7.Sub(startTime7)

	averageDuration7 := totalDuration / time.Duration(numRuns)

	fmt.Printf("AIGCReq Time with t = %d, n = %d: %s\n", threshold, n, averageDuration7)

	g2k := new(bn128.G2).ScalarMult(gp.G2, k)

	forenValid, _ := aigc.AIGCForen(gp, pi, pip, g2k)
	fmt.Println("The result of AIGCForen", forenValid)
	startTime8 := time.Now()
	for i := 0; i < numRuns*aigc_n; i++ {
		_, _ = aigc.AIGCForen(gp, pi, pip, g2k)
	}
	endTime8 := time.Now()
	totalDuration = endTime8.Sub(startTime8)

	averageDuration8 := totalDuration / time.Duration(numRuns)

	fmt.Printf("AIGCForen Time with t = %d, n = %d: %s\n", threshold, n, averageDuration8)

	fmt.Printf("AIGC Copyright Forensics total Time with t = %d, n = %d, agic_n = %d, aigc_size = %d: %s\n\n", threshold, n, aigc_n, size, averageDuration7+averageDuration8)

	fmt.Printf("The number of user N : %d \n", N)

	// pipArray := make([]*bn128.G1, N)
	// piArray := make([]*bn128.GT, N)

	// for i := 0; i < N; i++ {
	// 	piArray[i] = pi
	// 	pipArray[i] = pip
	// }

	// g2kArray := make([]*bn128.G2, N)
	// for i := 0; i < N; i++ {
	// 	g2kArray[i] = g2k
	// }

	// batchValid, _ := aigc.BatchAIGCForen(gp, piArray, pipArray, N, g2kArray)
	// fmt.Println("The result of BatchAIGCForen", batchValid)

	// startTime9 := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = aigc.BatchAIGCForen(gp, piArray, pipArray, N, g2kArray)
	// }
	// endTime9 := time.Now()
	// totalDuration = endTime9.Sub(startTime9)

	// averageDuration9 := totalDuration / time.Duration(numRuns)

	// fmt.Printf("BatchAIGCForen Time with t = %d, n = %d: %s\n", threshold, n, averageDuration9)

	// fmt.Printf("AIGC Copyright Forensics total Time with t = %d, n = %d: %s\n\n", threshold, n, averageDuration7+averageDuration9)

	// ========== Trace ==========
	fmt.Print("===========Trace============\n")
	sx, piShares := aigc.Trace(gp, cpk.Cpk1, sShares, I)

	// startTimeA := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = aigc.Trace(gp, cpk.Cpk1, sShares, I)
	// }
	// endTimeA := time.Now()
	// totalDuration = endTimeA.Sub(startTimeA)

	// averageDurationA := totalDuration / time.Duration(numRuns)

	// fmt.Printf("Trace Time with t = %d, n = %d: %s\n", threshold, n, averageDurationA)

	traceValid, _ := aigc.TraceVer(gp, piShares, cpk.Cpk1, sx, I)
	fmt.Println("The result of TraceVer", traceValid)

	// startTimeB := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = aigc.TraceVer(gp, piShares, cpk.Cpk1, sx, I)
	// }
	// endTimeB := time.Now()
	// totalDuration = endTimeB.Sub(startTimeB)

	// averageDurationB := totalDuration / time.Duration(numRuns)

	// fmt.Printf("TraceVer Time with t = %d, n = %d: %s\n\n", threshold, n, averageDurationB)

	// AIGC Copyright Transfer

	fmt.Print("===========Transfer============\n")
	nta, pkc2, req2, pi_req2, r2, k2, _ := aigc.TransInit(gp, m, pkc, commitment[0])
	// startTimeC := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _, _, _, _, _, _ = aigc.TransInit(gp, m, pkc, commitment[0])
	// }
	// endTimeC := time.Now()
	// totalDuration = endTimeC.Sub(startTimeC)

	input := append(pkc2.Marshal(), m...)
	// H(pkc || m)
	hashPointG1 := aigc.HashToG1(input)

	// averageDurationC := totalDuration / time.Duration(numRuns)

	// fmt.Printf("TransInit Time with t = %d, n = %d: %s\n", threshold, n, averageDurationC)

	_, _, _, valid, _ := aigc.TransProof(gp, m, k, k2, r2, nta, g2k, pkc2, req2, hashPointG1, ursk.U2, cpk.Cpk2, cpk2Shares, cskShares, pi_req2, commitment, I)
	fmt.Println("Verify result of Transfer", valid)

	// startTimeD := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _, _, _, _ = aigc.TransProof(gp, m, k, k2, r2, nta, g2k, pkc2, req2, hashPointG1, ursk.U2, cpk.Cpk2, cpk2Shares, cskShares, pi_req2, commitment, I)
	// }
	// endTimeD := time.Now()
	// totalDuration = endTimeD.Sub(startTimeD)

	// averageDurationD := totalDuration / time.Duration(numRuns)

	// fmt.Printf("TransProof Time with t = %d, n = %d: %s\n", threshold, n, averageDurationD)
}
