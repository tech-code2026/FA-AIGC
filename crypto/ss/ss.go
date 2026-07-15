package ss

import (
	bn128 "aigc/bn128"
	"crypto/rand"
	"errors"
	"math/big"
	// bn128 "github.com/cloudflare/bn256"
)

// Public parameters
type PubPara struct {
	Order *big.Int
	N     int
	T     int
}

// var G = new(bn128.G1).ScalarBaseMult(big.NewInt(1))

// Generate public parameters
func Setup(n, t int) (*PubPara, error) {
	order := bn128.Order
	pub := &PubPara{
		Order: order,
		N:     n,
		T:     t,
	}
	return pub, nil
}

func Share(pub *PubPara, s *big.Int) ([]*big.Int, error) {
	// Generate a random polynomial (coefficients)
	coefficients := make([]*big.Int, pub.T)
	coefficients[0] = s
	for i := 1; i < pub.T; i++ {
		coefficients[i], _ = rand.Int(rand.Reader, pub.Order)
	}
	// Calculate the secret shares
	shares := make([]*big.Int, pub.N)
	for i := 0; i < pub.N; i++ {
		shares[i] = EvaluatePolynomial(coefficients, big.NewInt(int64(i+1)), pub.Order)
	}
	return shares, nil
}

// Reconstruct the secret
// I is the index of the shares used by the reconstruction (0-based 索引)
func Recon(I []int, shares []*big.Int, pub *PubPara) (*big.Int, error) {
	// fmt.Printf("Recon Debug: len(I)=%d, len(shares)=%d, I=%v\n", len(I), len(shares), I)
	lambdas, _ := PrecomputeLagCoef(pub, I)
	secret := big.NewInt(0)
	for i := 0; i < len(I); i++ {
		// lambda_i := lambdas[i]
		idx := I[i]
		temp := new(big.Int).Mul(shares[idx], lambdas[i])
		secret.Add(secret, temp)
		secret.Mod(secret, pub.Order)
	}
	return secret.Mod(secret, pub.Order), nil
}

// (s1+s2)Shares
func AddHomomorphic(shares1, shares2 []*big.Int, pub *PubPara) ([]*big.Int, error) {
	if len(shares1) != len(shares2) {
		return nil, errors.New("share length mismatch")
	}
	n := len(shares1)
	res := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		res[i] = new(big.Int).Add(shares1[i], shares2[i])
		res[i].Mod(res[i], pub.Order)
	}
	return res, nil
}

// (s1*s2)Shares
func MulHomomorphic(shares1, shares2 []*big.Int, pub *PubPara) ([]*big.Int, error) {
	n := pub.N
	p := pub.Order

	if len(shares1) != n || len(shares2) != n {
		return nil, errors.New("share length mismatch with pub.N")
	}

	// --- 深拷贝输入 shares，防止修改原始数据 ---
	sh1 := make([]*big.Int, n)
	sh2 := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		sh1[i] = new(big.Int).Set(shares1[i])
		sh2[i] = new(big.Int).Set(shares2[i])
	}

	// 1. compute y_i = s1_i * s2_i mod p
	y := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		y[i] = new(big.Int).Mul(sh1[i], sh2[i])
		y[i].Mod(y[i], p)
	}

	// 2. compute Lagrange coefficients l_i(0)
	l0, err := ComputeL0(pub)
	if err != nil {
		return nil, err
	}

	// 3. compute constants c_i = y_i * l0[i] mod p
	c := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		c[i] = new(big.Int).Mul(y[i], l0[i])
		c[i].Mod(c[i], p)
	}

	// 4. each participant generates a new t-1 degree polynomial for c_i
	reshared := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		reshared[i], err = Share(pub, c[i])
		if err != nil {
			return nil, err
		}
	}

	// 5. aggregate: final share j = sum_i reshared[i][j] mod p
	finalShares := make([]*big.Int, n)
	for j := 0; j < n; j++ {
		sum := big.NewInt(0)
		for i := 0; i < n; i++ {
			sum.Add(sum, reshared[i][j])
			sum.Mod(sum, p)
		}
		finalShares[j] = sum
	}

	return finalShares, nil
}

// ComputeL0 computes Lagrange coefficients l_i(0) for all shares
func ComputeL0(pub *PubPara) ([]*big.Int, error) {
	n := pub.N
	p := pub.Order
	l0 := make([]*big.Int, n)

	// xs = 1..N
	xs := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		xs[i] = big.NewInt(int64(i + 1))
	}

	for i := 0; i < n; i++ {
		li := big.NewInt(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			num := new(big.Int).Neg(xs[j]) // 0 - x_j
			num.Mod(num, p)
			den := new(big.Int).Sub(xs[i], xs[j]) // x_i - x_j
			den.Mod(den, p)
			denInv := new(big.Int).ModInverse(den, p)
			if denInv == nil {
				return nil, errors.New("no modular inverse in ComputeL0")
			}
			li.Mul(li, num)
			li.Mul(li, denInv)
			li.Mod(li, p)
		}
		l0[i] = li
	}

	return l0, nil
}

func ReconG1(I []int, shares []*bn128.G1, pub *PubPara) (*bn128.G1, error) {
	lambdas, err := PrecomputeLagCoef(pub, I)
	if err != nil {
		return nil, err
	}
	// 初始化结果 G1 := 0*G
	secretG1 := new(bn128.G1).ScalarBaseMult(big.NewInt(0))
	// 累加每个份额乘以对应拉格朗日系数
	for i := 0; i < len(I); i++ {
		idx := I[i] // shares 下标是 0..N-1
		temp := new(bn128.G1).ScalarMult(shares[idx], lambdas[i])
		secretG1.Add(secretG1, temp)
	}
	return secretG1, nil
}

func ReconG2(I []int, shares []*bn128.G2, pub *PubPara) (*bn128.G2, error) {
	lambdas, err := PrecomputeLagCoef(pub, I)
	if err != nil {
		return nil, err
	}

	secretG1 := new(bn128.G2).ScalarBaseMult(big.NewInt(0))

	for i := 0; i < len(I); i++ {
		idx := I[i] // shares 下标是 0..N-1
		temp := new(bn128.G2).ScalarMult(shares[idx], lambdas[i])
		secretG1.Add(secretG1, temp)
	}
	return secretG1, nil
}

func ReconGT(I []int, shares []*bn128.GT, pub *PubPara) (*bn128.GT, error) {
	lambdas, err := PrecomputeLagCoef(pub, I)
	if err != nil {
		return nil, err
	}

	secretG1 := new(bn128.GT).ScalarBaseMult(big.NewInt(0))

	for i := 0; i < len(I); i++ {
		idx := I[i] // shares 下标是 0..N-1
		temp := new(bn128.GT).ScalarMult(shares[idx], lambdas[i])
		secretG1.Add(secretG1, temp)
	}
	return secretG1, nil
}

// Precompute the coefficients of the Lagrange interpolation polynomial
func PrecomputeLagCoef(pub *PubPara, I []int) ([]*big.Int, error) {
	if len(I) < pub.T {
		return nil, errors.New("not enough shares to recover the secret")
	}
	// Compute lambda: the Lagrange Coefficients
	lambdas := make([]*big.Int, len(I))
	for i := 0; i < len(I); i++ {
		alpha_i := big.NewInt(int64(I[i]) + 1)
		lambda_i := big.NewInt(1)
		for j := 0; j < len(I); j++ {
			if i != j {
				alpha_j := big.NewInt(int64(I[j]) + 1)
				// λ_i = λ_i * (0 - α_j) / (α_i - α_j) mod p
				num := new(big.Int).Sub(big.NewInt(0), alpha_j)
				den := new(big.Int).Sub(alpha_i, alpha_j)
				den.ModInverse(den, pub.Order)

				lambda_i.Mul(lambda_i, num)
				lambda_i.Mul(lambda_i, den)
				lambda_i.Mod(lambda_i, pub.Order)
			}
		}
		lambdas[i] = lambda_i
	}
	return lambdas, nil
}

// Compute the value of the polynomial point x
func EvaluatePolynomial(coefficients []*big.Int, x, order *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[0])
	xPower := new(big.Int).Set(x)

	for i := 1; i < len(coefficients); i++ {
		term := new(big.Int).Mul(coefficients[i], xPower)
		term.Mod(term, order)
		result.Add(result, term)
		result.Mod(result, order)
		xPower.Mul(xPower, x)
		xPower.Mod(xPower, order)
	}

	return result
}
