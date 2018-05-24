pragma solidity ^0.4.22;

import "./Debuggable.sol";
import "./ECMathInterface.sol";
import "./libBulletproofStruct.sol";

contract BulletproofVerify is ECMathInterface {
	uint256 private NCurve; //Stored locally in order to minimize ECMath calls

	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address _ecMathAddr) ECMathInterface(_ecMathAddr) public {
	    RefreshECMathParameters();
	}
	
	//Update locally stored ECMath parameters
	function RefreshECMathParameters() ownerOnly requireECMath public {
	    NCurve = ecMath.GetNCurve();
	}
    
	//Verify single bullet proof
	struct Variables {
	    //Fiat-Shamir Challenges
		uint256 x;
		uint256 y;
		uint256 z;
		uint256 k;
		uint256 x_ip;
		
		//M = # of commitments
		//N = # of bits
		uint256 logMN;
		uint256 maxMN;
		uint256 M;
		
		uint256 gs;         //Scalar for Gi generator points
		uint256 hs;         //Scalar for Hi generator points
		uint256[] vp2;      //[2^0, 2^1, ..., 2^(N-1)]
		uint256[] vpy;      //[y^0, y^1, ..., y^(M*N-1)]
		uint256[] vpyi;     //[y^0, y^(-1), ..., y^(1-M*N)]
		uint256[] vpz;      //[z^0, z^1, ..., z^(M-1)]
		
		uint256[] w;        //More Fiat-Shamir Challenges
		uint256[] wi;       //w[]^(-1)
		uint256[] Gi;       //Generator points: [H2P(H), H2P(Hi[0]), H2P(Hi[1]), ...] 
		uint256[] Hi;       //Generator points: [H2P(Gi[0]), H2P(Gi[1]), H2P(Gi[2])...]
		
		uint256 weight;     //Weight for each batched proof
		
		//Batched proof checks
		//Stage 1 Checks
		uint256 y0;         //taux
		uint256 y1;         //t-(k+z+vSum(vpy))
		uint256[2] Y2;      //z-vSum(V)
		uint256[2] Y3;      //xT1
		uint256[2] Y4;      //(x^2)*T2
		
		//Stage 2 Checks
		uint256[2] Z0;      //A + xS
		uint256 z1;         //mu
		uint256[2] Z2;      //Li and Ri sum
		uint256 z3;         //(t-a*b)*x_ip
		uint256[] z4;       //sum(gs)
		uint256[] z5;       //sum(hs)
		uint256[2] point;   //Temporary point
	}
	
	//Verify Bulletproof(s), can do multiple commitements and multiple proofs at once
	function VerifyBulletproof(BulletproofStruct.Data[] bp)
	    internal constant requireECMath returns (bool) {
	    //Find longest proof
	    Variables memory v;
	    uint256 p;
	    for (p = 0; p < bp.length; p++) {
	        if (bp[p].L.length > v.maxMN) {
	            v.maxMN = bp[p].L.length;
	        }
	    }
	    v.maxMN = 2**(v.maxMN / 2);
	    
	    //Make sure we have enough Gi and Hi base points
	    if(v.maxMN > ecMath.GetGiHiLength()) return false;
	    
	    //Fetch Gi and Hi base points
		(v.Gi, v.Hi) = ecMath.GetGiHi(v.maxMN);
	    
	    //Initialize z4 and z5 checks
	    v.z4 = new uint256[](v.maxMN);
	    v.z5 = new uint256[](v.maxMN);
	    
	    //Populate check variables for each proof
	    for (p = 0; p < bp.length; p++) {
	        //Do input checks
	        if (bp[p].V.length < 2) return false;
	        if (bp[p].V.length % 2 != 0) return false;
	        if (bp[p].L.length < 2) return false;
	        if (bp[p].L.length % 2 != 0) return false;
	        if (bp[p].R.length != bp[p].L.length) return false;
	        
	        v.logMN = (bp[p].L.length / 2);
	        v.M = 2**(v.logMN) / bp[p].N;
	        
	        //Pick *random* weight, not sure if this works...
	        //Probably need a better source of randomness
	        if (bp.length > 1) {
	            v.weight = uint256(keccak256(blockhash(p), gasleft(), v.weight)) % NCurve;
	        }
	        
	        //Start hashing for Fiat-Shamir
    		v.y = uint256(keccak256(	Keccak256OfArray(bp[p].V),
    									bp[p].A[0], bp[p].A[1],
    									bp[p].S[0], bp[p].S[1]	)) % NCurve;
    											
    		v.z = uint256(keccak256(	v.y	)) % NCurve;
    		
    		v.x = uint256(keccak256(	v.z,
    									bp[p].T1[0], bp[p].T1[1],
    									bp[p].T2[0], bp[p].T2[1]	)) % NCurve;
    											
    		v.x_ip = uint256(keccak256(	v.x,
    									bp[p].taux, bp[p].mu, bp[p].t	)) % NCurve;
	        
	        //Calculate k
	        v.vp2 = vPow(2, bp[p].N);
	        v.vpy = vPow(v.y, v.M*bp[p].N);
	        v.vpyi = vPow(sInv(v.y), v.M*bp[p].N);
	        
	        v.k = sMul(sSq(v.z), vSum(v.vpy));
	        uint256 j;
	        for (j = 1; j <= v.M; j++) {
	            v.k = sAdd(v.k, sMul(sPow(v.z, j+2), vSum(v.vp2)));
	        }
	        v.k = sNeg(v.k);
	        
	        //Compute inner product challenges
	        v.w = new uint256[](v.logMN);
	        v.wi = new uint256[](v.logMN);
	        
    		v.w[0] = uint256(keccak256(	v.x_ip,
    									bp[p].L[0], bp[p].L[1],
    									bp[p].R[0], bp[p].R[1])) % NCurve;
    		v.wi[0] = sInv(v.w[0]);
    									
		    uint256 i;
    		uint256 index = 2;							
    		for (i = 1; i < v.logMN; i++) {
    		    v.w[i] = uint256(keccak256(	v.w[i-1],
    									    bp[p].L[index], bp[p].L[index+1],
    									    bp[p].R[index], bp[p].R[index+1])) % NCurve;
    		    
    		    v.wi[i] = sInv(v.w[i]);

    			index += 2;
    		}
		    
		    //Compute base point scalars and calulcate z4 and z5
		    for (i = 0; i < (v.M*bp[p].N); i++) {
		        v.gs = bp[p].a;
		        v.hs = sMul(bp[p].b, v.vpyi[i]);
		        
		        uint256 J;
		        for (J = 0; J < v.logMN; J++) {
		            j = v.logMN - J - 1;
		            
		            if (i & (1 << j) == 0) {
		                v.gs = sMul(v.gs, v.wi[J]);
		                v.hs = sMul(v.hs, v.w[J]);
		            }
		            else {
		                v.gs = sMul(v.gs, v.w[J]);
		                v.hs = sMul(v.hs, v.wi[J]);
		            }
		        }
		        
		        v.gs = sAdd(v.gs, v.z);
		        v.hs = sSub(v.hs, sMul(sAdd(sMul(v.z, v.vpy[i]), sMul(sPow(v.z, 2+(i / bp[p].N)), v.vp2[i%bp[p].N])), v.vpyi[i]));
		    
		        //If only one proof, weights are not needed
		        if (bp.length == 1) {
		            v.z4[i] = sNeg(v.gs);
		            v.z5[i] = sNeg(v.hs);
		        }
		        else {
    		        v.z4[i] = sSub(v.z4[i], sMul(v.gs, v.weight));
    		        v.z5[i] = sSub(v.z5[i], sMul(v.hs, v.weight));
		        }
		    }
		    
		    //Calculate y0, y1, Y2, Y3, Y4, Z0, z1, Z2, and z3 for checks
		    //If only one proof, weights are not needed and some simplications can be made
		    if (bp.length == 1) {
		        v.y0 = bp[0].taux;
		        v.y1 = sSub(bp[0].t, sAdd(v.k, sMul(v.z, vSum(v.vpy))));
		        
		        v.vpz = vPow(v.z, v.M);
		        v.vpz = vScale(v.vpz, sSq(v.z));
		        v.Y2 = ecMath.MultiExp(bp[0].V, v.vpz, 0, 0);
		        
		        v.Y3 = ecMath.Multiply(bp[0].T1, v.x);
		        v.Y4 = ecMath.Multiply(bp[0].T2, sSq(v.x));
		        
		        v.Z0 = ecMath.AddMultiply(bp[0].A, bp[0].S, v.x);
		        v.z1 = bp[0].mu;
		        
		        v.w = vMul(v.w, v.w);
		        v.wi = vMul(v.wi, v.wi);
		        v.Z2 = ecMath.MultiExp(bp[0].L, v.w, 0, 0);
		        v.Z2 = ecMath.AddMultiExp(v.Z2, bp[0].R, v.wi, 0, 0);
		        
		        v.z3 = sMul(sSub(bp[0].t, sMul(bp[0].a, bp[0].b)), v.x_ip);
		    }
		    else {
		        v.y0 = sAdd(v.y0, sMul(bp[p].taux, v.weight));
                v.y1 = sAdd(v.y1, sMul(sSub(bp[p].t, sAdd(v.k, sMul(v.z, vSum(v.vpy)))), v.weight));
		        
		        v.vpz = vPow(v.z, v.M);
		        v.vpz = vScale(v.vpz, sSq(v.z));
		        v.point = ecMath.MultiExp(bp[p].V, v.vpz, 0, 0);
		        v.Y2 = ecMath.AddMultiply(v.Y2, v.point, v.weight);
		        
		        v.Y3 = ecMath.AddMultiply(v.Y3, ecMath.Multiply(bp[p].T1, v.x), v.weight);
		        v.Y4 = ecMath.AddMultiply(v.Y4, ecMath.Multiply(bp[p].T2, sSq(v.x)), v.weight);
		    
		        v.Z0 = ecMath.AddMultiply(v.Z0, ecMath.AddMultiply(bp[p].A, bp[p].S, v.x), v.weight);
		        v.z1 = sAdd(v.z1, sMul(bp[p].mu, v.weight));
		        
		        v.w = vMul(v.w, v.w);
		        v.wi = vMul(v.wi, v.wi);
		        v.point = ecMath.MultiExp(bp[p].L, v.w, 0, 0);
		        v.point = ecMath.AddMultiExp(v.point, bp[p].R, v.wi, 0, 0);
		        v.Z2 = ecMath.AddMultiply(v.Z2, v.point, v.weight);
		        
		        v.z3 = sAdd(v.z3, sMul(sMul(sSub(bp[p].t, sMul(bp[p].a, bp[p].b)), v.x_ip), v.weight));
		    }
	    }
		
		//Perform checks on all proof(s) at once
		//Stage 1 Checks
		v.point = ecMath.CommitG1H(v.y0, v.y1);
		v.point = ecMath.Subtract(v.point, v.Y2);
		v.point = ecMath.Subtract(v.point, v.Y3);
		
		if (!ecMath.Equals(v.point, v.Y4)) {
		    /*emit DebugEvent("check1 failed!", 1);
		    emit DebugEvent("y0", v.y0);
		    emit DebugEvent("y1", v.y1);
		    emit DebugEvent("Y2", ecMath.CompressPoint(v.Y2));
		    emit DebugEvent("Y3", ecMath.CompressPoint(v.Y3));
		    emit DebugEvent("Y4", ecMath.CompressPoint(v.Y4));*/
		    return false;
		}
		
		//Stage 2 Checks
		v.point = ecMath.AddMultiplyG1(v.Z0, sNeg(v.z1));
		v.point = ecMath.AddMultiplyH(v.point, v.z3);
		v.point = ecMath.AddMultiExp(v.point, v.Gi, v.z4, 0, 0);
		v.point = ecMath.AddMultiExp(v.point, v.Hi, v.z5, 0, 0);
		
		if (!ecMath.Equals(v.point, ecMath.Negate(v.Z2))) {
		    /*emit DebugEvent("check2 failed!", 1);
		    emit DebugEvent("Z0", ecMath.CompressPoint(v.Z0));
		    emit DebugEvent("z1", v.z1);
		    emit DebugEvent("Z2", ecMath.CompressPoint(v.Z2));
		    emit DebugEvent("z3", v.z3);
		    emit DebugEvent2("z4[]", v.z4);
		    emit DebugEvent2("z5[]", v.z5);*/
		    return false;
		}
		else {
		    return true;
		}
	}
	
	//Serialized version of VerifyBulletproof() for external calling
	function VerifyBulletproof(uint256[] argsSerialized) public view returns (bool) {
		return VerifyBulletproof(BulletproofStruct.Deserialize(argsSerialized));
	}
	
	//Low level helper functions
	function sNeg(uint256 a) internal view returns (uint256 out) {
		out = NCurve - (a % NCurve);
	}
	
	function sAdd(uint256 a, uint256 b) internal view returns (uint256 out) {
		out = addmod(a, b, NCurve);
	}
	
	function sSub(uint256 a, uint256 b) internal view returns (uint256 out) {
		out = addmod(a, sNeg(b), NCurve);
	}
	
	function sMul(uint256 a, uint256 b) internal view returns (uint256 out) {
		out = mulmod(a, b, NCurve);
	}
	
	function sSq(uint256 a) internal view returns (uint256 out) {
		out = mulmod(a, a, NCurve);
	}
	
	function sPow(uint256 a, uint256 p) internal view returns (uint256 out) {
		out = a;
		for (uint256 i = 1; i < p; i++) {
			out = mulmod(out, a, NCurve);
		}
	}
	
	function sInv(uint256 a) internal view returns (uint256 out) {
		a = a % NCurve;
		require(a > 0);
			
        int256 t1;
        int256 t2 = 1;
        uint256 r1 = NCurve;
        uint256 r2 = a;
        uint256 q;
        
		while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int(q) * t2, r2, r1 - q * r2);
        }
		
        if (t1 < 0)
			out = (NCurve - uint256(-t1));
		else
			out = uint256(t1);
		
		if (sMul(a, out) != 1) revert();
		
        return out;
    }
	
	function vPow(uint256 x, uint256 N) internal view returns (uint256[] out) {
		out = new uint256[](N);
		
		if (x > 0) {
			out[0] = 1;
			for (uint256 i = 1; i < N; i++) {
				out[i] = sMul(out[i-1], x); 
			}
		}
	}
	
	function vSum(uint256[] a) internal view returns (uint256 out) {
		require(a.length > 0);
		
		out = a[0];
		for (uint256 i = 1; i < a.length; i++) {
			out = sAdd(out, a[i]);
		}
	}
	
	function vMul(uint256[] a, uint256[] b) internal view returns (uint256[] out) {
 		require(a.length > 0);
 		require(a.length == b.length);
 		
 		out = new uint256[](a.length);
 
 		for (uint256 i = 0; i < a.length; i++) {
 			out[i] = sMul(a[i], b[i]);
 		}
 	}
 	
 	function vScale(uint256[] a, uint256 s) internal view returns (uint256[] out) {
		require(a.length > 0);
		
		out = new uint256[](a.length);

		for (uint256 i = 0; i < a.length; i++) {
			out[i] = sMul(a[i], s);
		}
	}
	
    //Calculate keccak256 of given array
    function Keccak256OfArray(uint256[] array)
        public pure returns (uint256 out)
    {
        uint256 len = array.length + 1;
        uint256[1] memory temp;
        
        //Construct c1 (store in c[0])
    	assembly {
    	    let p := mload(0x40)
    	    mstore(p, mul(len, 0x20)) //0x20 = 32; 32 bytes for array length + 32 bytes per uint256
    	    mstore(temp, keccak256(array, mload(p)))
    	}
    	
    	out = temp[0];
    }
}

