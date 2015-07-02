package vote

import "crypto/elliptic"
import "math/big"
import "math/rand"
import "testing"

func TestDiscreteLog(t *testing.T) {
	c := elliptic.P256()
	var xprime *big.Int
	var yprime *big.Int
	for i := 0; i < 10; i++ {
		j := rand.Int63n(120)
		xprime, yprime = c.ScalarBaseMult(big.NewInt(j).Bytes())
		jn, _ := DiscreteLog(xprime, yprime, c, 120)
		if j != int64(jn) {
			t.Fail()
		}
	}
}
