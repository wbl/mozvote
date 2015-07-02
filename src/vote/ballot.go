package vote

import "bytes"
import "errors"
import "math/big"
import "crypto/elliptic"
import "crypto/rand"
import "crypto/sha256"

type Ballot struct {
	boxes []*Checkbox
	c     *big.Int
	r     *big.Int
}

type Reckoning struct {
	marks []*Mark
}

func FillBallot(c elliptic.Curve, px *big.Int, py *big.Int, entry int,
	size int) *Ballot {
	b := new(Ballot)
	b.boxes = make([]*Checkbox, size, size)
	for i := 0; i < size; i++ {
		if i == entry {
			b.boxes[i] = VoteOne(c, px, py)
		} else {
			b.boxes[i] = VoteZero(c, px, py)
		}
	}
	//TODO: add validation
	//Let A be the sum of all the A, B the sum of all the B
	//Then we want log_g(A)=log_h(B-g)

	ax := big.NewInt(0)
	ay := big.NewInt(0)
	bx := big.NewInt(0)
	by := big.NewInt(0)
	s := big.NewInt(0)
	for i := 0; i < size; i++ {
		ax, ay = c.Add(ax, ay, b.boxes[i].ax, b.boxes[i].ay)
		bx, by = c.Add(bx, by, b.boxes[i].bx, b.boxes[i].by)
		s.Add(s, b.boxes[i].s)
	}
	s.Mod(s, c.Params().N)
	k, err := rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		panic("Not here, not now")
	}
	v1x, v1y := c.ScalarBaseMult(k.Bytes())
	v2x, v2y := c.ScalarMult(px, py, k.Bytes())
	var commit [4][]byte
	commit[0] = elliptic.Marshal(c, ax, ay)
	commit[1] = elliptic.Marshal(c, bx, by)
	commit[2] = elliptic.Marshal(c, v1x, v1y)
	commit[3] = elliptic.Marshal(c, v2x, v2y)
	cb := bytes.Join(commit[:], []byte{})
	cbytes := sha256.Sum256(cb[:])
	b.c = big.NewInt(0)
	b.c.SetBytes(cbytes[:])
	b.c.Mod(b.c, c.Params().N)
	b.r = big.NewInt(0)
	//r=k-c*s
	b.r.Mul(b.c, s)
	b.r.Sub(k, b.r)
	b.r.Mod(b.r, c.Params().N)
	return b
}

func IsValidBallot(c elliptic.Curve, px *big.Int, py *big.Int, b *Ballot) bool {
	valid := true
	for i := 0; i < len(b.boxes); i++ {
		valid = valid && IsValidBox(c, b.boxes[i], px, py)
	}
	if !valid {
		return false
	}
	//Time to go do some work
	//TODO: fix all additions (elsewhere in file to use fact
	//that Go handles identity as (0,0)
	ax := big.NewInt(0)
	ay := big.NewInt(0)
	bx := big.NewInt(0)
	by := big.NewInt(0)
	for i := 0; i < len(b.boxes); i++ {
		ax, ay = c.Add(ax, ay, b.boxes[i].ax, b.boxes[i].ay)
		bx, by = c.Add(bx, by, b.boxes[i].bx, b.boxes[i].by)
	}
	t := big.NewInt(0)
	t.Neg(c.Params().Gy)
	t.Mod(t, c.Params().P)
	bgx, bgy := c.Add(bx, by, c.Params().Gx, t)
	v1x, v1y := doublescalarmult(c, c.Params().Gx, c.Params().Gy,
		b.r.Bytes(), ax, ay, b.c.Bytes())
	v2x, v2y := doublescalarmult(c, px, py, b.r.Bytes(),
		bgx, bgy, b.c.Bytes())
	var commit [4][]byte
	commit[0] = elliptic.Marshal(c, ax, ay)
	commit[1] = elliptic.Marshal(c, bx, by)
	commit[2] = elliptic.Marshal(c, v1x, v1y)
	commit[3] = elliptic.Marshal(c, v2x, v2y)
	cb := bytes.Join(commit[:], []byte{})
	cbytes := sha256.Sum256(cb[:])
	challenge := big.NewInt(0)
	challenge.SetBytes(cbytes[:])
	challenge.Mod(challenge, c.Params().N)
	if challenge.Cmp(b.c) != 0 {
		return false
	} else {
		return true
	}
}

func ExtractReckoning(b *Ballot) *Reckoning {
	size := len(b.boxes)
	r := new(Reckoning)
	r.marks = make([]*Mark, size, size)
	for i := 0; i < size; i++ {
		r.marks[i] = ExtractMark(b.boxes[i])
	}
	return r
}

func SumReckonings(c elliptic.Curve, l []*Reckoning) *Reckoning {
	num := len(l)
	if num == 1 {
		return l[0]
	} else {
		r := new(Reckoning)
		size := len(l[0].marks)
		r.marks = make([]*Mark, size, size)
		copy(r.marks, l[0].marks)
		for i := 1; i < num; i++ {
			for j := 0; j < size; j++ {
				r.marks[j] = AddMarks(c, r.marks[j],
					l[i].marks[j])
			}
		}
		return r
	}
}

func DecryptResults(c elliptic.Curve, priv []byte,
	r *Reckoning) ([]int, error) {
	size := len(r.marks)
	t := make([]int, size, size)
	for i := 0; i < size; i++ {
		v, err := DecryptMark(c, r.marks[i], priv)
		if err != nil {
			return nil, err
		}
		t[i] = v
	}
	return t, nil
}

func MarshalBallot(c elliptic.Curve, b *Ballot) []byte {
	/* The format is very simple: first 4 bytes are length of ballot
	   Then that many serialized checkboxes, one after the other
	   lastly, (c, r) */
	numballots := len(b.boxes)
	bytelen := (c.Params().BitSize + 7) >> 3
	ballotlen := 2 + 8*bytelen //Result of not compressing
	size := 4 + numballots*ballotlen + 2*bytelen
	ret := make([]byte, size, size)
	ret[0] = byte((numballots >> 24) & 0xff)
	ret[1] = byte((numballots >> 16) & 0xff)
	ret[2] = byte((numballots >> 8) & 0xff)
	ret[3] = byte(numballots & 0xff)
	for i := 0; i < numballots; i++ {
		copy(ret[i*ballotlen+4:(i+1)*ballotlen+4],
			MarshalCheckbox(c, b.boxes[i]))
	}
	cbytes := b.c.Bytes()
	copy(ret[numballots*ballotlen+4+bytelen-len(cbytes):], cbytes)
	rbytes := b.r.Bytes()
	copy(ret[numballots*ballotlen+4+2*bytelen-len(rbytes):], rbytes)
	return ret
}

func UnmarshalBallot(c elliptic.Curve, bytes []byte) (*Ballot, error) {
	if len(bytes) < 4 {
		return nil, errors.New("Not long enough!")
	}
	numballots := int(bytes[0])<<24 + int(bytes[1])<<16 +
		int(bytes[2])<<8 + int(bytes[3])
	ret := new(Ballot)
	ret.boxes = make([]*Checkbox, numballots, numballots)
	bytesize := (c.Params().BitSize + 7) >> 3
	ballotlen := 2 + 8*bytesize
	if len(bytes) != 4+numballots*ballotlen+2*bytesize {
		return nil, errors.New("Wrong length!")
	}
	for i := 0; i < numballots; i++ {
		ret.boxes[i] = UnmarshalCheckbox(c, bytes[i*ballotlen+4:(i+1)*ballotlen+4])
		if ret.boxes[i] == nil {
			return nil, errors.New("Incorrect serialization")
		}
	}
	ret.c = new(big.Int)
	ret.c.SetBytes(bytes[numballots*ballotlen+4 : numballots*ballotlen+
		4+bytesize])
	ret.r = new(big.Int)
	ret.r.SetBytes(bytes[numballots*ballotlen+4+bytesize : numballots*ballotlen+4+2*bytesize])
	return ret, nil
}

func MarshalReckoning(c elliptic.Curve, r *Reckoning) []byte {
	num := len(r.marks)
	bytesize := (c.Params().BitSize + 7) >> 3
	marklen := 2 + 4*bytesize
	totsize := 4 + marklen*num
	ret := make([]byte, totsize, totsize)
	ret[0] = byte((num >> 24) & 0xff)
	ret[1] = byte((num >> 16) & 0xff)
	ret[2] = byte((num >> 8) & 0xff)
	ret[3] = byte((num) & 0xff)
	for i := 0; i < num; i++ {
		copy(ret[i*marklen+4:(i+1)*marklen+4], MarshalMark(c, r.marks[i]))
	}
	return ret
}

func UnmarshalReckoning(c elliptic.Curve, bytes []byte) (*Reckoning, error) {
	if len(bytes) < 4 {
		return nil, errors.New("Insufficient length")
	}
	num := int(bytes[0])<<24 + int(bytes[1])<<16 + int(bytes[2])<<8 + int(bytes[3])
	bytesize := (c.Params().BitSize + 7) >> 3
	marklen := 2 + 4*bytesize
	if len(bytes) != marklen*num+4 {
		return nil, errors.New("Incorrect length")
	}
	ret := new(Reckoning)
	ret.marks = make([]*Mark, num, num)
	for i := 0; i < num; i++ {
		ret.marks[i] = UnmarshalMark(c, bytes[i*marklen+4:(i+1)*marklen+4])
	}
	return ret, nil
}
