package vote

import "crypto/elliptic"
import "crypto/rand"
import "testing"

func TestCheckandMarks5(t *testing.T) {
	var votes [5]*Checkbox
	var marks [5]*Mark
	c := elliptic.P256()
	priv, px, py, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fail()
	}
	for i := 0; i < 5; i++ {
		if i%2 == 0 {
			vote := VoteOne(c, px, py)
			votes[i] = UnmarshalCheckbox(c,
				MarshalCheckbox(c, vote))
		} else {
			votes[i] = VoteZero(c, px, py)
		}
	}
	for i := 0; i < 5; i++ {
		if !IsValidBox(c, votes[i], px, py) {
			t.Fail()
		}
		marks[i] = UnmarshalMark(c, MarshalMark(c, ExtractMark(votes[i])))
		res, bad := DecryptMark(c, marks[i], priv)
		if bad != nil {
			t.Log("invalid vote", i)
			t.Log(marks[i].ax, marks[i].ay,
				marks[i].bx, marks[i].by)
		} else {
			t.Log("vote ", i, " was ", res)
		}
	}

	final := SumMarks(c, marks[:])
	res, bad := DecryptMark(c, final, priv)
	if bad != nil {
		t.Log("failed decryption")
	} else {
		t.Log("got", res, "as result")
	}
	if (bad != nil) || (res != 3) {
		t.Fail()
	}
}

func NegativeTest(t *testing.T) {
	var vote *Checkbox
	c := elliptic.P256()
	_, px, py, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fail()
	}
	vote = VoteZero(c, px, py)
	vote.c1, err = rand.Int(rand.Reader, c.Params().N)
	if err != nil {
		t.Fail()
	}
	if IsValidBox(c, vote, px, py) {
		t.Fail()
	}
}

func BenchmarkVerify(b *testing.B) {
	c := elliptic.P256()
	_, px, py, _ := elliptic.GenerateKey(c, rand.Reader)
	box := VoteZero(c, px, py)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidBox(c, box, px, py)
	}
}
