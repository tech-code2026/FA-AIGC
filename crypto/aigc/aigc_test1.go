package aigc

import (
	bn128 "aigc/bn128"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

const mib = 1024 * 1024

// -----------------------------------------------------------------------------
// How to run:
//
//   go test -run 'TestAIGCExp' -timeout 0 -count=1 -v
//
// Output CSV files are written to ./test_results by default.
//
// Optional environment variables:
//   AIGC_OUT_DIR=./test_results      output directory
//   AIGC_SCALE_REPEATS=1             repeated measurements for count/size experiments
//   AIGC_BOX_REPEATS=30              repeated measurements for boxplot experiments
//   AIGC_DELAY_STD_MS=10             Gaussian random delay standard deviation in ms
//   AIGC_REAL_SLEEP_DELAY=0          if 1, actually sleep for simulated delay
//
// Notes:
//   1. Message size uses MiB, i.e., 1 MiB = 1024 * 1024 bytes.
//   2. Registration stage = CopyReq + AIGCReg.
//   3. Forensics stage = AIGCReq + AIGCForen.
//   4. The delay experiment models t committee nodes replying in parallel; therefore,
//      the effective network waiting time is max_i(baseDelay + GaussianNoise_i).
// -----------------------------------------------------------------------------

type aigcBenchCtx struct {
	gp *GPar
	I  []int

	cskShares []*big.Int
	cpk       *cpk

	cpk1Shares []*bn128.G1
	cpk2Shares []*bn128.G2

	userSecret *big.Int
	sShares    []*big.Int
	rhoShares  []*big.Int
	commitment []*bn128.G1
	ursk       *ursk
}

type registrationRecord struct {
	T   *bn128.GT
	pkc *bn128.G2
}

func TestAIGCExp_MessageSizeScaling(t *testing.T) {
	ctx := newAIGCBenchCtx(t, 27, 14)
	sizesMiB := []int{1, 10, 100, 200, 400, 600, 800}
	repeats := envInt("AIGC_SCALE_REPEATS", 30)

	w, closeFn := newCSV(t, "aigc_message_size_scaling.csv", []string{
		"repeat",
		"n",
		"threshold_t",
		"message_count",
		"message_size_mib",
		"message_size_bytes",
		"registration_ms",
		"forensics_ms",
	})
	defer closeFn()

	for rep := 0; rep < repeats; rep++ {
		for _, sizeMiB := range sizesMiB {
			msg := makeMessage(sizeMiB*mib, uint64(rep*10_000+sizeMiB))

			rec, regDur, err := runRegistrationStage(ctx, msg)
			if err != nil {
				t.Fatalf("registration failed: repeat=%d sizeMiB=%d: %v", rep, sizeMiB, err)
			}

			forenDur, err := runForensicsStage(ctx, rec, msg)
			if err != nil {
				t.Fatalf("forensics failed: repeat=%d sizeMiB=%d: %v", rep, sizeMiB, err)
			}

			writeCSV(t, w, []string{
				strconv.Itoa(rep),
				strconv.Itoa(ctx.gp.Par.N),
				strconv.Itoa(ctx.gp.Par.T),
				"1",
				strconv.Itoa(sizeMiB),
				strconv.Itoa(len(msg)),
				ms(regDur),
				ms(forenDur),
			})
			t.Logf("[size] repeat=%d size=%dMiB registration=%s forensics=%s",
				rep, sizeMiB, regDur, forenDur)

			msg = nil
			runtime.GC()
		}
	}
}

func TestAIGCExp_DelayBoxplotData(t *testing.T) {
	ctx := newAIGCBenchCtx(t, 27, 14)
	baseDelaysMs := []int{0, 50, 100, 200, 300, 400, 500}
	repeats := envInt("AIGC_BOX_REPEATS", 30)
	delayStdMs := envFloat("AIGC_DELAY_STD_MS", 10.0)
	realSleep := envBool("AIGC_REAL_SLEEP_DELAY", false)

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	msg := makeMessage(1*mib, 0)

	w, closeFn := newCSV(t, "aigc_delay_boxplot.csv", []string{
		"trial",
		"phase",
		"n",
		"threshold_t",
		"message_size_mib",
		"fixed_delay_ms",
		"gaussian_std_ms",
		"simulated_network_delay_ms",
		"crypto_ms",
		"total_ms",
		"delay_model",
	})
	defer closeFn()

	for trial := 0; trial < repeats; trial++ {
		for _, baseMs := range baseDelaysMs {
			stampMessage(msg, uint64(trial*10_000+baseMs))

			rec, regCryptoDur, err := runRegistrationStage(ctx, msg)
			if err != nil {
				t.Fatalf("registration failed: trial=%d delay=%dms: %v", trial, baseMs, err)
			}
			regNetDur := gaussianParallelThresholdDelay(ctx.gp.Par.T, float64(baseMs), delayStdMs, rng)
			if realSleep {
				time.Sleep(regNetDur)
			}
			writeCSV(t, w, []string{
				strconv.Itoa(trial),
				"registration",
				strconv.Itoa(ctx.gp.Par.N),
				strconv.Itoa(ctx.gp.Par.T),
				"1",
				strconv.Itoa(baseMs),
				fmt.Sprintf("%.6f", delayStdMs),
				ms(regNetDur),
				ms(regCryptoDur),
				ms(regCryptoDur + regNetDur),
				"parallel_max_of_t_gaussian_delays",
			})

			forenCryptoDur, err := runForensicsStage(ctx, rec, msg)
			if err != nil {
				t.Fatalf("forensics failed: trial=%d delay=%dms: %v", trial, baseMs, err)
			}
			forenNetDur := gaussianParallelThresholdDelay(ctx.gp.Par.T, float64(baseMs), delayStdMs, rng)
			if realSleep {
				time.Sleep(forenNetDur)
			}
			writeCSV(t, w, []string{
				strconv.Itoa(trial),
				"forensics",
				strconv.Itoa(ctx.gp.Par.N),
				strconv.Itoa(ctx.gp.Par.T),
				"1",
				strconv.Itoa(baseMs),
				fmt.Sprintf("%.6f", delayStdMs),
				ms(forenNetDur),
				ms(forenCryptoDur),
				ms(forenCryptoDur + forenNetDur),
				"parallel_max_of_t_gaussian_delays",
			})

			t.Logf("[delay] trial=%d base=%dms registration_total=%s forensics_total=%s",
				trial, baseMs, regCryptoDur+regNetDur, forenCryptoDur+forenNetDur)
		}
	}
}

func TestAIGCExp_TraceUserBoxplotData(t *testing.T) {
	ctx := newAIGCBenchCtx(t, 27, 14)
	userNumbers := []int{10, 20, 40, 60, 80}
	repeats := envInt("AIGC_BOX_REPEATS", 30)
	maxUsers := userNumbers[len(userNumbers)-1]

	userShares := make([][]*big.Int, maxUsers)
	for i := 0; i < maxUsers; i++ {
		s := randomScalar(t, ctx.gp.Par.Order)
		sShares, _, _, err := RegReq(ctx.gp, s)
		if err != nil {
			t.Fatalf("RegReq failed while preparing trace users: user=%d: %v", i, err)
		}
		userShares[i] = sShares
	}

	w, closeFn := newCSV(t, "aigc_trace_user_boxplot.csv", []string{
		"trial",
		"n",
		"threshold_t",
		"user_number",
		"trace_total_ms",
		"trace_avg_per_user_ms",
	})
	defer closeFn()

	for trial := 0; trial < repeats; trial++ {
		for _, userNumber := range userNumbers {
			start := time.Now()

			for i := 0; i < userNumber; i++ {
				sx, piShares := Trace(ctx.gp, ctx.cpk.Cpk1, userShares[i], ctx.I)
				ok, err := TraceVer(ctx.gp, piShares, ctx.cpk.Cpk1, sx, ctx.I)
				if err != nil {
					t.Fatalf("TraceVer failed: trial=%d userNumber=%d i=%d: %v", trial, userNumber, i, err)
				}
				if !ok {
					t.Fatalf("TraceVer returned false: trial=%d userNumber=%d i=%d", trial, userNumber, i)
				}
			}

			total := time.Since(start)
			writeCSV(t, w, []string{
				strconv.Itoa(trial),
				strconv.Itoa(ctx.gp.Par.N),
				strconv.Itoa(ctx.gp.Par.T),
				strconv.Itoa(userNumber),
				ms(total),
				ms(total / time.Duration(userNumber)),
			})
			t.Logf("[trace] trial=%d users=%d total=%s", trial, userNumber, total)
		}
	}
}

func newAIGCBenchCtx(tb testing.TB, n, threshold int) *aigcBenchCtx {
	tb.Helper()

	gp, err := GlobalSetup(n, threshold)
	if err != nil {
		tb.Fatalf("GlobalSetup failed: %v", err)
	}

	I := firstThresholdIndexes(threshold)

	cskShares, committeePK, err := DKGen(gp)
	if err != nil {
		tb.Fatalf("DKGen failed: %v", err)
	}

	cpk1Shares := make([]*bn128.G1, gp.Par.N)
	cpk2Shares := make([]*bn128.G2, gp.Par.N)
	for i := 0; i < gp.Par.N; i++ {
		cpk1Shares[i] = new(bn128.G1).ScalarMult(gp.G1, cskShares[i])
		cpk2Shares[i] = new(bn128.G2).ScalarMult(gp.G2, cskShares[i])
	}

	userSecret := randomScalar(tb, gp.Par.Order)
	sShares, rhoShares, commitment, err := RegReq(gp, userSecret)
	if err != nil {
		tb.Fatalf("RegReq failed: %v", err)
	}

	urskShares, err := KGenIssue(gp, cskShares, sShares, rhoShares, commitment, I)
	if err != nil {
		tb.Fatalf("KGenIssue failed: %v", err)
	}

	userSK, err := KeyRecon(gp, urskShares, I)
	if err != nil {
		tb.Fatalf("KeyRecon failed: %v", err)
	}

	g1s := new(bn128.G1).ScalarMult(gp.G1, userSecret)
	ok, err := KeyVer(gp, committeePK.Cpk1, userSK, g1s)
	if err != nil {
		tb.Fatalf("KeyVer failed: %v", err)
	}
	if !ok {
		tb.Fatalf("KeyVer returned false")
	}

	return &aigcBenchCtx{
		gp:         gp,
		I:          I,
		cskShares:  cskShares,
		cpk:        committeePK,
		cpk1Shares: cpk1Shares,
		cpk2Shares: cpk2Shares,
		userSecret: userSecret,
		sShares:    sShares,
		rhoShares:  rhoShares,
		commitment: commitment,
		ursk:       userSK,
	}
}

func runRegistrationStage(ctx *aigcBenchCtx, msg []byte) (registrationRecord, time.Duration, error) {
	start := time.Now()

	sigmaShares, pkc, r, k, _, _, err := CopyReq(ctx.gp, msg, ctx.cskShares)
	if err != nil {
		return registrationRecord{}, 0, err
	}

	T, err := AIGCReg(ctx.gp, sigmaShares, ctx.ursk.U2, ctx.cpk2Shares, ctx.cpk.Cpk2, r, k, msg, pkc, ctx.I)
	if err != nil {
		return registrationRecord{}, 0, err
	}

	return registrationRecord{T: T, pkc: pkc}, time.Since(start), nil
}

func runForensicsStage(ctx *aigcBenchCtx, rec registrationRecord, msg []byte) (time.Duration, error) {
	start := time.Now()

	pi, pip, _, _, _, err := AIGCReq(
		ctx.gp,
		rec.T,
		msg,
		rec.pkc,
		ctx.cskShares,
		ctx.sShares,
		ctx.rhoShares,
		ctx.cpk1Shares,
		ctx.cpk2Shares,
		ctx.I,
		ctx.commitment,
	)
	if err != nil {
		return 0, err
	}

	ok, err := AIGCForen(ctx.gp, pi, pip, rec.pkc)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("AIGCForen returned false")
	}

	return time.Since(start), nil
}

func firstThresholdIndexes(threshold int) []int {
	I := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = i
	}
	return I
}

func randomScalar(tb testing.TB, order *big.Int) *big.Int {
	tb.Helper()

	for {
		x, err := crand.Int(crand.Reader, order)
		if err != nil {
			tb.Fatalf("random scalar generation failed: %v", err)
		}
		if x.Sign() != 0 {
			return x
		}
	}
}

func makeMessage(sizeBytes int, id uint64) []byte {
	msg := make([]byte, sizeBytes)
	stampMessage(msg, id)
	return msg
}

func stampMessage(msg []byte, id uint64) {
	if len(msg) >= 8 {
		binary.LittleEndian.PutUint64(msg[len(msg)-8:], id)
		return
	}
	for i := range msg {
		msg[i] = byte(id >> (8 * uint(i%8)))
	}
}

func gaussianParallelThresholdDelay(threshold int, baseMs, stdMs float64, rng *mrand.Rand) time.Duration {
	var maxMs float64
	for i := 0; i < threshold; i++ {
		d := baseMs + rng.NormFloat64()*stdMs
		if d < 0 {
			d = 0
		}
		if d > maxMs {
			maxMs = d
		}
	}
	return time.Duration(maxMs * float64(time.Millisecond))
}

func newCSV(tb testing.TB, filename string, header []string) (*csv.Writer, func()) {
	tb.Helper()

	outDir := envString("AIGC_OUT_DIR", "test_results")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		tb.Fatalf("failed to create output directory %q: %v", outDir, err)
	}

	path := filepath.Join(outDir, filename)
	f, err := os.Create(path)
	if err != nil {
		tb.Fatalf("failed to create csv %q: %v", path, err)
	}

	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		_ = f.Close()
		tb.Fatalf("failed to write csv header %q: %v", path, err)
	}

	tb.Logf("writing CSV: %s", path)

	return w, func() {
		w.Flush()
		if err := w.Error(); err != nil {
			tb.Fatalf("csv writer error for %q: %v", path, err)
		}
		if err := f.Close(); err != nil {
			tb.Fatalf("failed to close csv %q: %v", path, err)
		}
	}
}

func writeCSV(tb testing.TB, w *csv.Writer, row []string) {
	tb.Helper()

	if err := w.Write(row); err != nil {
		tb.Fatalf("failed to write csv row: %v", err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		tb.Fatalf("csv writer error: %v", err)
	}
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.6f", float64(d.Nanoseconds())/1e6)
}

func envString(name, fallback string) string {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	return v
}

func envInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envFloat(name string, fallback float64) float64 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	x, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return x
}

func envBool(name string, fallback bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
