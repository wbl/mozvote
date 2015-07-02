package vote

import "crypto/elliptic"
import "math/big"
import "errors"

func DiscreteLog(x *big.Int, y *big.Int, c elliptic.Curve, bound int) (int, error) {
	var xprime *big.Int
	var yprime *big.Int
	if x.Cmp(big.NewInt(0)) == 0 && y.Cmp(big.NewInt(0)) == 0 {
		return 0, nil
	}
	for i := 0; i < bound; i++ {
		xprime, yprime = c.ScalarBaseMult(big.NewInt(int64(i)).Bytes())
		if xprime.Cmp(x) == 0 && yprime.Cmp(y) == 0 {
			return i, nil
		}
	}
	return -1, errors.New("log not found")
}
