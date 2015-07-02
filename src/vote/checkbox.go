package vote

import "bytes"
import "crypto/elliptic"
import "crypto/rand"
import "crypto/sha256"
import "math/big"

type Checkbox struct {
	ax *big.Int //x coordinate of ephemeral point
	ay *big.Int //y coordinate of ephemeral point
	bx *big.Int //x coordinate of message
	by *big.Int //y coordinate of message
	c1 *big.Int //c1, c2, r1, r2 used in proof of validity
	c2 *big.Int
	r1 *big.Int
	r2 *big.Int
	s  *big.Int //private scalar used for proofs
}

type Mark struct {
	ax *big.Int
	ay *big.Int
	bx *big.Int
	by *big.Int
}

func doublescalarmult(c elliptic.Curve, ax *big.Int, ay *big.Int, s1 []byte,
	bx *big.Int, by *big.Int, s2 []byte) (*big.Int, *big.Int) {
	t1x, t1y := c.ScalarMult(ax, ay, s1)
	t2x, t2y := c.ScalarMult(bx, by, s2)
	return c.Add(t1x, t1y, t2x, t2y)
}

func IsValidBox(c elliptic.Curve, box *Checkbox,
	px *big.Int, py *big.Int) bool {
	if !c.IsOnCurve(box.ax, box.ay) ||
		!c.IsOnCurve(box.bx, box.by) {
		return false
	}
	//Explanation of how this works
	//(c1,r1) validates equality of log g A and log p B-g
	//(c2, r2) validates euqality of log g A and log p B
	//each of these proofs is just a Schnorr proof of knowledge of
	//the log, which work for both simultaneously
	//We require c1+c2=H(A, B t1,t2,t3,t4) which enforces that only one
	//of these can be faked, hence giving an or proof
	v1x, v1y := doublescalarmult(c, c.Params().Gx, c.Params().Gy,
		box.r1.Bytes(), box.ax, box.ay, box.c1.Bytes())
	t4x := c.Params().Gx
	t4y := new(big.Int)
	t4y.Neg(c.Params().Gy)
	t4y.Mod(t4y, c.Params().P)
	bgx, bgy := c.Add(box.bx, box.by, t4x, t4y)
	v2x, v2y := doublescalarmult(c, px, py, box.r1.Bytes(),
		bgx, bgy, box.c1.Bytes())
	v3x, v3y := doublescalarmult(c, c.Params().Gx, c.Params().Gy,
		box.r2.Bytes(), box.ax, box.ay, box.c2.Bytes())
	v4x, v4y := doublescalarmult(c, px, py, box.r2.Bytes(),
		box.bx, box.by, box.c2.Bytes())
	var entries [6][]byte
	entries[0] = elliptic.Marshal(c, box.ax, box.ay)
	entries[1] = elliptic.Marshal(c, box.bx, box.by)
	entries[2] = elliptic.Marshal(c, v1x, v1y)
	entries[3] = elliptic.Marshal(c, v2x, v2y)
	entries[4] = elliptic.Marshal(c, v3x, v3y)
	entries[5] = elliptic.Marshal(c, v4x, v4y)
	challenge := sha256.Sum256(bytes.Join(entries[:], []byte{}))
	ctot := big.NewInt(0)
	ctot.SetBytes(challenge[:])
	ctot.Mod(ctot, c.Params().N)
	t := big.NewInt(0)
	t.Add(box.c1, box.c2)
	t.Mod(t, c.Params().N)
	if t.Cmp(ctot) != 0 {
		return false
	}
	return true
}

func VoteOne(c elliptic.Curve, px *big.Int, py *big.Int) *Checkbox {
	var err error
	h := new(Checkbox)
	h.s, err = rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		panic("this shouldn't happen")
	}
	h.ax, h.ay = c.ScalarBaseMult(h.s.Bytes())
	tx, ty := c.ScalarMult(px, py, h.s.Bytes())
	h.bx, h.by = c.Add(tx, ty, c.Params().Gx, c.Params().Gy)
	//TODO: refactor: lots of similar logic here but parts very
	//c2, r2 fake, c1 r1 genuine
	//Form the faked challenge
	h.c2, err = rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		panic("this shouldn't happen")
	}
	h.r2, err = rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		panic("this shouldn't happen")
	}
	//Compute the commitments v3, v4 as the verifier will
	v3x, v3y := doublescalarmult(c, c.Params().Gx, c.Params().Gy, h.r2.Bytes(),
		h.ax, h.ay, h.c2.Bytes())
	v4x, v4y := doublescalarmult(c, px, py, h.r2.Bytes(),
		h.bx, h.by, h.c2.Bytes())
	//Commit to other side
	s1, err := rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		panic("something deeply wrong")
	}
	v1x, v1y := c.ScalarBaseMult(s1.Bytes())
	v2x, v2y := c.ScalarMult(px, py, s1.Bytes())
	//Compute the total challenge
	var entries [6][]byte
	entries[0] = elliptic.Marshal(c, h.ax, h.ay)
	entries[1] = elliptic.Marshal(c, h.bx, h.by)
	entries[2] = elliptic.Marshal(c, v1x, v1y)
	entries[3] = elliptic.Marshal(c, v2x, v2y)
	entries[4] = elliptic.Marshal(c, v3x, v3y)
	entries[5] = elliptic.Marshal(c, v4x, v4y)
	challenge := sha256.Sum256(bytes.Join(entries[:], []byte{}))
	ctot := big.NewInt(0)
	ctot.SetBytes(challenge[:])
	ctot.Mod(ctot, c.Params().N)
	h.c1 = big.NewInt(0)
	h.c1.Sub(ctot, h.c2)
	h.c1.Mod(h.c1, c.Params().N)
	//r=s1-c1*h.s
	t := big.NewInt(0)
	t.Mul(h.c1, h.s)
	t.Mod(t, c.Params().N)
	t.Sub(s1, t)
	t.Mod(t, c.Params().N)
	h.r1 = t
	return h
}

func VoteZero(c elliptic.Curve, px *big.Int, py *big.Int) *Checkbox {
	var err error
	h := new(Checkbox)
	h.s, err = rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		panic("this shouldn't happen")
	}
	h.ax, h.ay = c.ScalarBaseMult(h.s.Bytes())
	h.bx, h.by = c.ScalarMult(px, py, h.s.Bytes())
	//TODO: get the proof generated
	//c1, r1 fake,  c2, r2 genuine
	//First compute the missing B-g
	tx := big.NewInt(0)
	tx.Set(c.Params().Gx)
	ty := big.NewInt(0)
	ty.Set(c.Params().Gy)
	ty.Neg(ty)
	ty.Mod(ty, c.Params().P)
	bgx, bgy := c.Add(tx, ty, h.bx, h.by)
	//Now fake the challenge
	h.c1, err = rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		panic("this shouldn't happen")
	}
	h.r1, err = rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		panic("this shouldn't happen")
	}
	//Compute v1, v2 as verifier will
	v1x, v1y := doublescalarmult(c, c.Params().Gx, c.Params().Gy,
		h.r1.Bytes(), h.ax, h.ay, h.c1.Bytes())
	v2x, v2y := doublescalarmult(c, px, py, h.r1.Bytes(),
		bgx, bgy, h.c1.Bytes())
	//Other part of commitment
	s1, err := rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		panic("something is deeply wrong")
	}
	v3x, v3y := c.ScalarBaseMult(s1.Bytes())
	v4x, v4y := c.ScalarMult(px, py, s1.Bytes())
	//Compute total challenge
	var entries [6][]byte
	entries[0] = elliptic.Marshal(c, h.ax, h.ay)
	entries[1] = elliptic.Marshal(c, h.bx, h.by)
	entries[2] = elliptic.Marshal(c, v1x, v1y)
	entries[3] = elliptic.Marshal(c, v2x, v2y)
	entries[4] = elliptic.Marshal(c, v3x, v3y)
	entries[5] = elliptic.Marshal(c, v4x, v4y)
	challenge := sha256.Sum256(bytes.Join(entries[:], []byte{}))
	ctot := big.NewInt(0)
	ctot.SetBytes(challenge[:])
	ctot.Mod(ctot, c.Params().N)
	h.c2 = big.NewInt(0)
	h.c2.Sub(ctot, h.c1)
	h.c2.Mod(h.c2, c.Params().N)
	//r2=s1-c2*s
	h.r2 = big.NewInt(0)
	h.r2.Mul(h.c2, h.s)
	h.r2.Sub(s1, h.r2)
	h.r2.Mod(h.r2, c.Params().N)
	return h
}

func ExtractMark(box *Checkbox) *Mark {
	r := new(Mark)
	r.ax = box.ax
	r.bx = box.bx
	r.ay = box.ay
	r.by = box.by
	return r
}

func SumMarks(c elliptic.Curve, marks [](*Mark)) *Mark {
	ax := marks[0].ax
	ay := marks[0].ay
	bx := marks[0].bx
	by := marks[0].by
	for i := 1; i < len(marks); i++ {
		ax, ay = c.Add(ax, ay, marks[i].ax, marks[i].ay)
		bx, by = c.Add(bx, by, marks[i].bx, marks[i].by)
	}
	r := new(Mark)
	r.ax = ax
	r.ay = ay
	r.bx = bx
	r.by = by
	return r
}

func AddMarks(c elliptic.Curve, m1 *Mark, m2 *Mark) *Mark {
	r := new(Mark)
	r.ax, r.ay = c.Add(m1.ax, m1.ay, m2.ax, m2.ay)
	r.bx, r.by = c.Add(m1.bx, m1.by, m2.bx, m2.by)
	return r
}

func DecryptMark(c elliptic.Curve, m *Mark, priv []byte) (int, error) {
	tx, ty := c.ScalarMult(m.ax, m.ay, priv)
	tm := big.NewInt(0)
	tm.Sub(c.Params().P, ty)
	tm.Mod(tm, c.Params().P)
	px, py := c.Add(m.bx, m.by, tx, tm)
	return DiscreteLog(px, py, c, 1<<10)
}

func MarshalCheckbox(c elliptic.Curve, b *Checkbox) []byte {
	bytelen := (c.Params().BitSize + 7) >> 3
	pointlen := 1 + 2*bytelen
	scalarlen := bytelen
	outlen := 2*pointlen + 4*scalarlen
	ret := make([]byte, outlen, outlen)
	abytes := elliptic.Marshal(c, b.ax, b.ay)
	copy(ret, abytes)
	bbytes := elliptic.Marshal(c, b.bx, b.by)
	copy(ret[pointlen:], bbytes)
	c1bytes := b.c1.Bytes()
	copy(ret[2*pointlen+scalarlen-len(c1bytes):], c1bytes)
	c2bytes := b.c2.Bytes()
	copy(ret[2*pointlen+2*scalarlen-len(c2bytes):], c2bytes)
	r1bytes := b.r1.Bytes()
	copy(ret[2*pointlen+3*scalarlen-len(r1bytes):], r1bytes)
	r2bytes := b.r2.Bytes()
	copy(ret[2*pointlen+4*scalarlen-len(r2bytes):], r2bytes)
	return ret
}

func MarshalMark(c elliptic.Curve, m *Mark) []byte {
	bytelen := (c.Params().BitSize + 7) >> 3
	pointlen := 1 + 2*bytelen
	outlen := 2 * pointlen
	ret := make([]byte, outlen, outlen)
	abytes := elliptic.Marshal(c, m.ax, m.ay)
	copy(ret, abytes)
	bbytes := elliptic.Marshal(c, m.bx, m.by)
	copy(ret[pointlen:], bbytes)
	return ret
}

func UnmarshalCheckbox(c elliptic.Curve, bytes []byte) *Checkbox {
	bytelen := (c.Params().BitSize + 7) >> 3
	pointlen := 1 + 2*bytelen
	scalarlen := bytelen
	if len(bytes) != 2*pointlen+4*scalarlen {
		return nil
	}
	ret := new(Checkbox)
	ret.ax, ret.ay = elliptic.Unmarshal(c, bytes[:pointlen])
	ret.bx, ret.by = elliptic.Unmarshal(c, bytes[pointlen:2*pointlen])
	ret.c1 = new(big.Int)
	ret.c2 = new(big.Int)
	ret.r1 = new(big.Int)
	ret.r2 = new(big.Int)
	ret.c1.SetBytes(bytes[2*pointlen : 2*pointlen+scalarlen])
	ret.c2.SetBytes(bytes[2*pointlen+scalarlen : 2*pointlen+2*scalarlen])
	ret.r1.SetBytes(bytes[2*pointlen+2*scalarlen : 2*pointlen+3*scalarlen])
	ret.r2.SetBytes(bytes[2*pointlen+3*scalarlen : 2*pointlen+4*scalarlen])
	return ret
}

func UnmarshalMark(c elliptic.Curve, bytes []byte) *Mark {
	bytelen := (c.Params().BitSize + 7) >> 3
	pointlen := 1 + 2*bytelen
	if len(bytes) != 2*pointlen {
		return nil
	}
	ret := new(Mark)
	ret.ax, ret.ay = elliptic.Unmarshal(c, bytes[:pointlen])
	ret.bx, ret.by = elliptic.Unmarshal(c, bytes[pointlen:2*pointlen])
	return ret
}
