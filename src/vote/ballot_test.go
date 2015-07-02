package vote

import "testing"
import "crypto/elliptic"
import "crypto/rand"

func TestElection(t *testing.T) {
	c := elliptic.P256()
	var s [3]*Reckoning
	priv, px, py, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fail()
		return
	}
	b1, err := UnmarshalBallot(c,
		MarshalBallot(c, FillBallot(c, px, py, 0, 2)))
	if err != nil {
		t.Log(err.Error())
		t.Fail()
		return
	}
	b2 := FillBallot(c, px, py, 0, 2)
	b3 := FillBallot(c, px, py, 1, 2)
	if !(IsValidBallot(c, px, py, b1) && IsValidBallot(c, px, py, b2) &&
		IsValidBallot(c, px, py, b3)) {
		t.Log("Failed Validation")
		t.Fail()
	}
	s[0] = ExtractReckoning(b1)
	s[1] = ExtractReckoning(b2)
	s[2] = ExtractReckoning(b3)
	s[0], err = UnmarshalReckoning(c, MarshalReckoning(c, s[0]))
	if err != nil {
		t.Fail()
		return
	}
	result := SumReckonings(c, s[0:])
	answer, err := DecryptResults(c, priv, result)
	if err != nil {
		t.Fail()
		return
	}
	if len(answer) != 2 {
		t.Fail()
		return
	}
	if answer[0] != 2 && answer[1] != 1 {
		t.Fail()
	}
}
