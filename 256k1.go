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
	y2.Mod(y2, curve.Params().P) //y²%P

	x3 := new(big.Int).Mul(x, x) //x²
	x3.Mul(x3, x)                //x³

	x3.Add(x3, curve.Params().B) //x³+B
	x3.Mod(x3, curve.Params().P) //(x³+B)%P

	return x3.Cmp(y2) == 0
}

//TODO: double check if the function is okay
// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file.
func (curve p256k1Curve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	zinv := new(big.Int).ModInverse(z, curve.Params().P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.Params().P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.Params().P)
	return
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (curve p256k1Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z := new(big.Int).SetInt64(1)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z, x2, y2, z))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (curve p256k1Curve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.Params().P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.Params().P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.Params().P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.Params().P)
	h := new(big.Int).Sub(u2, u1)
	if h.Sign() == -1 {
		h.Add(h, curve.Params().P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.Params().P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.Params().P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.Params().P)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3 := new(big.Int).Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.Params().P)

	y3 := new(big.Int).Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.Params().P)

	z3 := new(big.Int).Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.Params().P)
	}
	z3.Sub(z3, z2z2)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.Params().P)
	}
	z3.Mul(z3, h)
	z3.Mod(z3, curve.Params().P)

	return x3, y3, z3
}

// Double returns 2*(x,y)
func (curve p256k1Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := new(big.Int).SetInt64(1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve p256k1Curve) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

	a := new(big.Int).Mul(x, x) //X1²
	b := new(big.Int).Mul(y, y) //Y1²
	c := new(big.Int).Mul(b, b) //B²

	d := new(big.Int).Add(x, b) //X1+B
	d.Mul(d, d)                 //(X1+B)²
	d.Sub(d, a)                 //(X1+B)²-A
	d.Sub(d, c)                 //(X1+B)²-A-C
	d.Mul(d, big.NewInt(2))     //2*((X1+B)²-A-C)

	e := new(big.Int).Mul(big.NewInt(3), a) //3*A
	f := new(big.Int).Mul(e, e)             //E²

	x3 := new(big.Int).Mul(big.NewInt(2), d) //2*D
	x3.Sub(f, x3)                            //F-2*D
	x3.Mod(x3, curve.Params().P)

	y3 := new(big.Int).Sub(d, x3)                  //D-X3
	y3.Mul(e, y3)                                  //E*(D-X3)
	y3.Sub(y3, new(big.Int).Mul(big.NewInt(8), c)) //E*(D-X3)-8*C
	y3.Mod(y3, curve.Params().P)

	z3 := new(big.Int).Mul(y, z) //Y1*Z1
	z3.Mul(big.NewInt(2), z3)    //3*Y1*Z1
	z3.Mod(z3, curve.Params().P)

	return x3, y3, z3
}

//TODO: double check if it is okay
// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (curve p256k1Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	// We have a slight problem in that the identity of the group (the
	// point at infinity) cannot be represented in (x, y) form on a finite
	// machine. Thus the standard add/double algorithm has to be tweaked
	// slightly: our initial state is not the identity, but x, and we
	// ignore the first true bit in |k|.  If we don't find any true bits in
	// |k|, then we return nil, nil, because we cannot return the identity
	// element.

	Bz := new(big.Int).SetInt64(1)
	x := Bx
	y := By
	z := Bz

	seenFirstTrue := false
	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			if seenFirstTrue {
				x, y, z = curve.doubleJacobian(x, y, z)
			}
			if byte&0x80 == 0x80 {
				if !seenFirstTrue {
					seenFirstTrue = true
				} else {
					x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
				}
			}
			byte <<= 1
		}
	}

	if !seenFirstTrue {
		return nil, nil
	}

	return curve.affineFromJacobian(x, y, z)
}

// ScalarBaseMult returns k*G, where G is the base point of the group and k is
// an integer in big-endian form.
func (curve p256k1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, k)
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
