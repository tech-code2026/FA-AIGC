// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
//pragma experimental ABIEncoderV2;

contract Verification
{



    // p = p(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1
    uint256 constant FIELD_ORDER = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Number of elements in the field (often called `q`)
    // n = n(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1


    uint256 constant GEN_ORDER = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 constant CURVE_B = 3;
    uint256 constant CURVE_A = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;
    uint256 internal constant FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

	struct G1Point {
		uint X;
		uint Y;
	}

	// Encoding of field elements is: X[0] * z + X[1]
	struct G2Point {
		uint[2] X;
		uint[2] Y;
	}

    G1Point G1 = G1Point(1, 2);
    G2Point G2 = G2Point(
        [11559732032986387107991004021392285783925812861821192530917403151452391805634,
        10857046999023057135944570762232829481370756359578518086990519993285655852781],
        [4082367875863433681332203403145435568316851327593401208105741076214120093531,
        8495653923123431417604973247489272438418190587263600148770280649306958101930]
    );


    int public MDA_i = 50; // minimum deposited assets
    int public a = 6;
    int public b = 3;

    function A() pure internal returns (uint256) {
		return CURVE_A;
	}

    function P() pure internal returns (uint256) {
        return FIELD_ORDER;
    }

    function N() pure internal returns (uint256) {
		return GEN_ORDER;
	}

    /// return the generator of G1
	function P1() pure internal returns (G1Point memory) {
		return G1Point(1, 2);
	}

    /// return the generator of G2
	function P2() pure internal returns (G2Point memory) {
		return G2Point(
			[11559732032986387107991004021392285783925812861821192530917403151452391805634,
			 10857046999023057135944570762232829481370756359578518086990519993285655852781],
			[4082367875863433681332203403145435568316851327593401208105741076214120093531,
			 8495653923123431417604973247489272438418190587263600148770280649306958101930]
		);
	}
    // G1Point G1 = G1Point(1, 2);

    function expMod(uint256 _base, uint256 _exponent, uint256 _modulus)
        internal view returns (uint256 retval)
    {
        bool success;
        uint256[1] memory output;
        uint[6] memory input;
        input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly {
            success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require(success);
        return output[0];
    }

    function modInverse(uint256 r) public view returns (uint256) {
        require(r > 0 && r < GEN_ORDER, "Invalid r for mod inverse");
        uint256 exponent = GEN_ORDER - 2;
        return expMod(r, exponent, GEN_ORDER);
    }

    /// return the sum of two points of G1
	function g1add(G1Point memory p1, G1Point memory p2) view internal returns (G1Point memory r) {
		uint[4] memory input;
		input[0] = p1.X;
		input[1] = p1.Y;
		input[2] = p2.X;
		input[3] = p2.Y;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
            // success := call(not(0), 0x06, 0, input, 128, r, 64)
		}
		// require(success);
        require(success, "elliptic curve addition failed");
	}


    function g1mul(G1Point memory p, uint s) view internal returns (G1Point memory r) {
		uint[3] memory input;
		input[0] = p.X;
		input[1] = p.Y;
		input[2] = s;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require(success, "elliptic curve multiplication failed");
	}

    function G1PointtoString(G1Point memory point) internal pure returns (string memory) {
        return string(abi.encodePacked(point.X, point.Y));
    }

    function pairing(G1Point[] memory p1, G2Point[] memory p2) view internal returns (bool) {
		require(p1.length == p2.length);
		uint elements = p1.length;
		uint inputSize = elements * 6;
		uint[] memory input = new uint[](inputSize);
		for (uint i = 0; i < elements; i++)
		{
			input[i * 6 + 0] = p1[i].X;
			input[i * 6 + 1] = p1[i].Y;
			input[i * 6 + 2] = p2[i].X[0];
			input[i * 6 + 3] = p2[i].X[1];
			input[i * 6 + 4] = p2[i].Y[0];
			input[i * 6 + 5] = p2[i].Y[1];
		}
		uint[1] memory out;
		bool success;
		assembly {
			success := staticcall(sub(gas()	, 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require(success);
		return out[0] != 0;
	}
	/// Convenience method for a pairing check for two pairs.
        // e(a1,a2) ?= e(b1,,b2)
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) view internal returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
	}


    function negate(G1Point memory p) public payable returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, FIELD_MODULUS - (p.Y % FIELD_MODULUS));
    }


    function precomputeLagCoef(uint256[] memory I) public view returns (uint256[] memory) {
        require(I.length >= par.t, "not enough shares to recover the secret");

        uint256[] memory lambdas = new uint256[](I.length);

        for (uint256 i = 0; i < I.length; i++) {
            uint256 alpha_i = I[i] + 1;
            
            uint256 lambda_i = 1;

            for (uint256 j = 0; j < I.length; j++) {
                if (i != j) {
                    uint256 alpha_j = I[j] + 1;
                    uint256 num = GEN_ORDER - (alpha_j % GEN_ORDER);

                    uint256 den;
                    if (alpha_i >= alpha_j) {
                        den = alpha_i - alpha_j;
                    } else {
                        den = GEN_ORDER - (alpha_j - alpha_i);
                    }
                    den = modInverse(den);

                    lambda_i = mulmod(lambda_i, num, GEN_ORDER);
                    lambda_i = mulmod(lambda_i, den, GEN_ORDER);
                }
            }
            lambdas[i] = lambda_i;
        }
        
        return lambdas;
    }

    function recon(uint256[] memory I, uint256[] memory shares) public view returns (uint256) {
        require(I.length > 0, "No shares to reconstruct");
        uint256[] memory lambdas = precomputeLagCoef(I);

        uint256 secret = 0;
        for (uint256 i = 0; i < I.length; i++) {
            uint256 idx = I[i];
            uint256 temp = mulmod(shares[idx], lambdas[i], GEN_ORDER);
            secret = addmod(secret, temp, GEN_ORDER);
        }
        return secret;
    }

    function reconG1(uint256[] memory I, G1Point[] memory shares) public view returns (G1Point memory) {
        require(I.length > 0, "No shares to reconstruct");

        uint256[] memory lambdas = precomputeLagCoef(I);

        G1Point memory secretG1 = G1Point(0, 0);

        for (uint256 i = 0; i < I.length; i++) {
            uint256 idx = I[i];
            
            G1Point memory temp = g1mul(shares[idx], lambdas[i]);
            if (secretG1.X == 0 && secretG1.Y == 0) {
                secretG1 = temp;
            } else {
                secretG1 = g1add(secretG1, temp);
            }
        }
        return secretG1;
    }

    // AIGC ===================================================================================================================================================================================================

    struct GPar {
        uint256 n;
        uint256 t;
    }

    GPar par;

    G1Point[] Commitment;


    // G1Point res;

    // HashToG1
    function HashToG1(bytes memory m) view internal returns (G1Point memory) {
        // 1. 计算 SHA256 哈希，并转换为 uint256 标量
        uint256 scalar = uint256(sha256(m));
        G1Point memory res = g1mul(G1, scalar);
        return res;
    }

    // uint256 resC;

    function hashToChallengeG1(G1Point memory g, G1Point memory y, G1Point memory t) pure internal returns (uint256) {
        bytes32 h = sha256(abi.encodePacked(g.X, g.Y, y.X, y.Y, t.X, t.Y));
        return uint256(h) % GEN_ORDER;
    }



    // function GetHashToG1() public view returns (G1Point memory){
    //     return res;
    // }

    function UploadGPar(uint256 n, uint256 t) public payable {  
        par.n = n;
        par.t = t; 
    }

    function UploadCommitment(G1Point[] memory commitment) public payable {
        // store commitment on blockchain
        for (uint i = 0; i < commitment.length; i++) {
            Commitment.push(commitment[i]);
        }
    }

    // store sigmaShares on blockchain
    // G1Point[] sigmaShares;

    // function CopyReq(bytes memory m, G1Point memory g1s, uint256 r, uint256[] memory cskShares) public payable returns (G1Point[] memory) {
    //     bytes memory input = abi.encodePacked(g1s.X, g1s.Y, m);
    //     G1Point memory hashPointG1 = HashToG1(input);
    //     G1Point memory res = g1mul(hashPointG1, r);
    //     for (uint i = 0; i < par.n; i++) {
    //         sigmaShares.push(g1mul(res, cskShares[i]));
    //     }
    //     return sigmaShares;
    // }

    // function GetCopyReqRes() public view returns (G1Point[] memory) {
    //     return sigmaShares;
    // }

    bool CopyReqVerRes;

    function CopyReq(G1Point memory hashPointG1, G1Point memory req, G1Point memory T, uint256 S) public payable returns (bool) {
        uint256 c = hashToChallengeG1(hashPointG1, req, T);
        G1Point memory left = g1mul(hashPointG1, S);
        G1Point memory right = g1add(T, g1mul(req, c));
        if (left.X == right.X && left.Y == right.Y) {
            CopyReqVerRes = true;        
        } else {
            CopyReqVerRes = false;
        }
        return CopyReqVerRes;
    }

    function GetCopyReqVerRes() public view returns (bool) {
        return CopyReqVerRes;
    }

    bool[] AIGCReqVerRes;

    bool[] AIGCRegVerRes;

    // G1Point sigma;

    function AIGCReg(G1Point[] memory sigmaShares, G2Point[] memory cpk2Shares, G2Point memory cpk2, G1Point memory req, G1Point memory sigma, G1Point memory hashPointG1) public payable {
        for (uint i = 0; i < par.t; i++) {
            if (!pairingProd2(sigmaShares[i], G2, negate(req), cpk2Shares[i])) {
                AIGCRegVerRes.push(false);
            }
            else {
                AIGCRegVerRes.push(true);
            }
        }
        // uint256 rInv = modInverse(r);
        // G1Point[] memory sigmaSharesRInv = new G1Point[](par.n);
        // for (uint i = 0; i < par.n; i++) {
        //     sigmaSharesRInv[i] = g1mul(sigmaShares[i], rInv);
        // }
        // G1Point memory sigma = reconG1(I,sigmaSharesRInv);

        if (!pairingProd2(sigma, G2, negate(hashPointG1), cpk2)) {
            AIGCRegVerRes.push(false);
        }
        else {
            AIGCRegVerRes.push(true);
        }

        // G1Point[] memory arrG1 = new G1Point[](1);
        // G2Point[] memory arrG2 = new G2Point[](1);
        // arrG1[0] = sigma;
        // arrG2[0] = cpk2;
        // pairing(arrG1,arrG2);

        // return sigma;
    }

    function GetAIGCRegVerRes() public view returns (bool []memory) {
        return AIGCRegVerRes;
    }

    function AIGCReq(G1Point memory hashPointG1, G1Point memory req2, G1Point memory T, uint256 S, G2Point[] memory cpk2Shares, G1Point[] memory K) public payable {
        uint256 c = hashToChallengeG1(hashPointG1, req2, T);
        G1Point memory left = g1mul(hashPointG1, S);
        G1Point memory right = g1add(T, g1mul(req2, c));
        if (left.X == right.X && left.Y == right.Y) {
            AIGCReqVerRes.push(true);        
        }
        else {
            AIGCReqVerRes.push(false);
        }

        for (uint i = 0; i < par.t; i++) {
            if (!pairingProd2(K[i], G2, negate(req2), cpk2Shares[i])) {
                AIGCReqVerRes.push(false);
            }
            else {
                AIGCReqVerRes.push(true);
            }
        }
    }

    function GetAIGCReqVerRes() public view returns (bool []memory) {
        return AIGCReqVerRes;
    }


    bool AIGCForenRes;

    function AIGCForen(G1Point memory pip, G1Point memory sigma, G2Point memory u2, uint256 exp) public payable returns (bool) {
        G1Point memory sigmap = g1mul(sigma, exp); 
        if (!pairingProd2(sigmap, u2, negate(pip), G2)) {
            AIGCForenRes = false;
        }
        else {
            AIGCForenRes = true;
        }
        return AIGCForenRes;
    }

    function GetAIGCForen() public view returns (bool) {
        return AIGCForenRes;
    }


    struct DLEQProof {
        G1Point a1;
        G1Point a2;
        uint256 c;
        uint256 z;
    }

    G1Point Nta;
    G1Point Reqp;
    G1Point Commitment0;

    bool TransferVerRes;

    function UploadTransfer(G1Point memory nta, G1Point memory reqp, G1Point memory commitment0) public payable {
        Nta = nta;
        Reqp = reqp;
        Commitment0 = commitment0;
    }

    DLEQProof proof;

    function UploadProof(G1Point memory a1, G1Point memory a2, uint256 c, uint256 z) public payable {
        proof.a1 = a1;
        proof.a2 = a2;
        proof.c = c;
        proof.z = z;
    }

    function VerifyTransfer(G1Point memory hashPointG1, G1Point memory T, uint256 S , G1Point memory X, G1Point memory g2k) public payable returns (bool) {
        uint256 c1 = hashToChallengeG1(hashPointG1, Reqp, T);
        G1Point memory left = g1mul(hashPointG1, S);
        G1Point memory right = g1add(T, g1mul(Reqp, c1));
        if (left.X != right.X || left.Y != right.Y) {
            TransferVerRes = false;        
            return false;
        } 
        G1Point memory gG = g1mul(Nta, proof.z);
        G1Point memory y1G = g1mul(X, proof.c);
        G1Point memory hG = g1mul(G1, proof.z);
        G1Point memory y2G = g1mul(g2k, proof.c);

        G1Point memory pt1 = g1add(gG, y1G);
        G1Point memory pt2 = g1add(hG, y2G);

        if ((proof.a1.X != pt1.X) || (proof.a1.Y != pt1.Y) || (proof.a2.X != pt2.X) || (proof.a2.Y != pt2.Y)) {
            TransferVerRes = false; 
            return false;
        }
        
        TransferVerRes = true;
        return true;
    }

    function GetTransferVerRes() public view returns (bool) {
        return TransferVerRes;
    }

    function Trace(G1Point memory Cpk1, uint256[] memory sxShares, uint256[] memory I) public payable returns (uint256) {
        uint256 sx = recon(I, sxShares);
        G1Point memory pi;
        for (uint i = 0; i < par.n; i++) {
            pi = g1mul(Cpk1, sxShares[i]);
        }
        return sx;
    }

    bool TracVerRes;

    function TraceVer(G1Point[] memory piShares, uint256 sx, G1Point memory Cpk1, uint256[] memory I) public payable returns (bool) {
        G1Point memory left = g1mul(Cpk1, sx);
        G1Point memory right = reconG1(I, piShares);
        if (left.X == right.X && left.Y == right.Y) {
            TracVerRes = true;
        }
        else {
            TracVerRes = false;
        }
        return TracVerRes;
    }

    function GetTraceVerRes() public view returns (bool) {
        return TracVerRes;
    }
}