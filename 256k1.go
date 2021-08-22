package crypto11

import (
	"crypto/elliptic"
	"math/big"
)

var p256k1 p256k1Curve

type p256k1Curve struct {
	*elliptic.CurveParams
}

func P256K1() elliptic.Curve {
	p256k1.CurveParams = &elliptic.CurveParams{Name: "P-256K1"}
	p256k1.P, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
	p256k1.N, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	p256k1.B, _ = new(big.Int).SetString("0x0000000000000000000000000000000000000000000000000000000000000007", 0)
	p256k1.Gx, _ = new(big.Int).SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
	p256k1.Gy, _ = new(big.Int).SetString("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
	p256k1.BitSize = 256

	return p256k1
}

func (curve p256k1Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (curve p256k1Curve) IsOnCurve(x, y *big.Int) bool {
	// y² = x³ + b
	y2 := new(big.Int).Mul(y, y) //y²
	y2.Mod(y2, curve.Params().P)       //y²%P

	x3 := new(big.Int).Mul(x, x) //x²
	x3.Mul(x3, x)                //x³

	x3.Add(x3, curve.Params().B) //x³+B
	x3.Mod(x3, curve.Params().P) //(x³+B)%P

	return x3.Cmp(y2) == 0
}

// func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
// 	byteLen := (curve.Params().BitSize + 7) / 8
// 	if len(data) != 1+2*byteLen {
// 		return nil, nil
// 	}
// 	if data[0] != 4 { // uncompressed form
// 		return nil, nil
// 	}
// 	p := curve.Params().P
// 	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
// 	y = new(big.Int).SetBytes(data[1+byteLen:])
// 	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
// 		log.Printf("Comparison failed for x or y")
// 		return nil, nil
// 	}
// 	if !curve.IsOnCurve(x, y) {
// 		log.Printf("IsOnCurve failed!")
// 		return nil, nil
// 	}
// 	return
// }
