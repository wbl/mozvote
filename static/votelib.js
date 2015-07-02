var mozvote = {
    _ansiserial: function(P){
	var x = P.x;
	var y = P.y;
	var startbyte = sjcl.codec.hex.toBits("0x04");
	var xbits = x.toBits(256);
	var ybits = y.toBits(256);
	return sjcl.bitArray.concat(sjcl.bitArray.concat(startbyte, xbits),
				    ybits);
    },
    
    vote: function (pubkey, zerone){
	if(zerone != 0 && zerone !=1){
	    return;
	}
	var decoded = sjcl.codec.base64.toBits(pubkey)
	var curve = sjcl.ecc.curves.c256
	var len = sjcl.bitArray.bitLength(decoded)
	var xbytes = sjcl.bitArray.bitSlice(decoded, 8, (len-8)/2+8);
	var ybytes = sjcl.bitArray.bitSlice(decoded, (len-8)/2+8, len);
	var pkey = new sjcl.ecc.point(curve, sjcl.bn.fromBits(xbytes),
				      sjcl.bn.fromBits(ybytes));
	var v = [];
	var scalar = sjcl.bn.random(curve.r.sub(1)).add(1);
	var A = curve.G.mult(scalar)
	var B = pkey.mult(scalar)
	if (zerone === 1) {
	    B = B.toJac().add(curve.G).toAffine();
	}
	var p = new sjcl.bn("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
	var s = sjcl.bn.random(curve.r);
	var Gsuby = p.sub(curve.G.y);
	var minG = new sjcl.ecc.point(curve, curve.G.x, Gsuby);
	var bg = B.toJac().add(minG).toAffine();
	if (zerone === 1) {
	    var c2 = sjcl.bn.random(curve.r);
	    var r2 = sjcl.bn.random(curve.r);
	    v[0] = curve.G.mult(s);
	    v[1] = pkey.mult(s);
	    v[2] = curve.G.mult2(r2, c2, A);
	    v[3] = pkey.mult2(r2, c2, B);
	} else {
	    var c1 = sjcl.bn.random(curve.r);
	    var r1 = sjcl.bn.random(curve.r);
	    v[0] = curve.G.mult2(r1, c1, A);
	    v[1] = pkey.mult2(r1, c1, bg);
	    v[2] = curve.G.mult(s);
	    v[3] = pkey.mult(s);
	}
	var commit = sjcl.bitArray.concat(mozvote._ansiserial(A),
					  mozvote._ansiserial(B));
	for(var i=0; i<4; i++){
	    commit = sjcl.bitArray.concat(commit, mozvote._ansiserial(v[i]));
	}
	var challenge = sjcl.bn.fromBits(sjcl.hash.sha256.hash(commit));
	challenge = challenge.mod(curve.r);
	if(zerone === 1){
	    var c1=challenge.sub(c2).mod(curve.r);
	    var r1=s.sub(scalar.mul(c1)).mod(curve.r);
	}else {
	    var c2 = challenge.sub(c1).mod(curve.r);
	    var r2 = s.sub(scalar.mul(c2)).mod(curve.r);
	}
    var rawballot = sjcl.bitArray.concat(mozvote._ansiserial(A),
					 mozvote._ansiserial(B));
	rawballot = sjcl.bitArray.concat(rawballot, c1.toBits(256));
	rawballot = sjcl.bitArray.concat(rawballot, c2.toBits(256));
	rawballot = sjcl.bitArray.concat(rawballot, r1.toBits(256));
	rawballot = sjcl.bitArray.concat(rawballot, r2.toBits(256));
	return sjcl.codec.base64.fromBits(rawballot);
    },
}
