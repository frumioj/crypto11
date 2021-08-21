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
