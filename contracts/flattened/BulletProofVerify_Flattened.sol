pragma solidity ^0.4.13;

contract Debuggable {
    //Debug Code
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier ownerOnly {
        if ( (msg.sender != owner) && (owner != 0) ) revert();
        _;
    }
    
	function Kill() public ownerOnly {
    	selfdestruct(msg.sender);
	}
	
	event DebugEvent(string marker, uint256 data);
	event DebugEvent2(string marker, uint256[] data);
}

contract ECMath {
	//Base EC Parameters
	function GetG1() public view returns (uint256[2]);
	function GetH() public view returns (uint256[2]);
	function GetInfinity() public view returns (uint256[2]);
	function GetNCurve() public pure returns (uint256);
	function GetPCurve() public pure returns (uint256);
	function GetGiHi(uint256 N) public constant returns (uint256[], uint256[]);
	function GetGiHiLength() public view returns (uint256);
	
	//Base EC Functions
	function Negate(uint256[2] p1) public pure returns (uint256[2] p2);
	function Equals(uint256[2] p1, uint256[2] p2) public pure returns (bool);
	function Add(uint256[2] p0, uint256[2] p1) public constant returns (uint256[2] p2);
	function Subtract(uint256[2] p0, uint256[2] p1) public constant returns (uint256[2] p2);
	function Multiply(uint256[2] p0, uint256 s) public constant returns (uint256[2] p1);
	
	//Shortcut Functions
	function MultiplyG1(uint256 s) public constant returns (uint256[2] p0);
	function MultiplyH(uint256 s) public constant returns (uint256[2] p0);
    function AddMultiply(uint256[2] p_add, uint256[2] p_mul, uint256 s) public constant returns (uint256[2] p0); //Returns p0 = p_add + s*p_mul
	function AddMultiplyG1(uint256[2] p_add, uint256 s) public constant returns (uint256[2] p0); //Returns p0 = p_add + s*G1
    function AddMultiplyH(uint256[2] p_add, uint256 s) public constant returns (uint256[2] p0); //Returns p0 = p_add + s*H
    function CommitG1H(uint256 s_G1, uint256 s_H) public constant returns (uint256[2] p0); //Returns s_G1*G1 + s_H*H
	
	//Vector Functions
	function VectorScale(uint256[] X, uint256 s) public constant returns (uint256[] Z);
	function VectorAdd(uint256[] X, uint256[] Y) public constant returns (uint256[] Z);
	function VectorMul(uint256[] X, uint256[] s) public constant returns (uint256[] Z);
	
	//Returns s0*P0 + s1*P1 + ... + sk*Pk
    function MultiExp(uint256[] P, uint256[] s, uint256 start, uint256 end) public constant returns (uint256[2] Pout);
	
	//Returns Pin + s0*P0 + s1*P1 + ... + sk*Pk
	function AddMultiExp(uint256[2] Pin, uint256[] P, uint256[] s, uint256 start, uint256 end) public constant returns (uint256[2] Pout);
	
	//Returns px = x[0]*X[0] + x[1]*X[1] + ... + x[n-1]*X[n-1]
    //    and py = y[0]*Y[0] + y[1]*Y[1] + ... + y[n-1]*Y[n-1]
    function CommitAB(uint256[] X, uint256[] Y, uint256[] x, uint256[] y) public constant returns (uint256[2] px, uint256[2] py);
        
	//Point Compression and Expansion Functions
	function CompressPoint(uint256[2] Pin) public pure returns (uint256 Pout);
	function EvaluateCurve(uint256 x) public constant returns (uint256 y, bool onCurve);
	function ExpandPoint(uint256 Pin) public constant returns (uint256[2] Pout);
	
	//Address Functions
	function GetAddress(uint256[2] PubKey) public pure returns (address addr);    
    function GetPublicKeyFromPrivateKey(uint256 privatekey) public constant returns (uint256[2] PubKey);    
    function GetAddressFromPrivateKey(uint256 privatekey) public constant returns (address addr);

    //Return H = keccak256(p)
    function HashOfPoint(uint256[2] point) public pure returns (uint256 h);
    
	//Return H = alt_bn128 evaluated at keccak256(p)
    function HashToPoint(uint256[2] p) public constant returns (uint256[2] h);
}

contract ECMathInterface is Debuggable {
    //Prerequisite Contract(s)
	ECMath ecMath;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function ECMath_GetAddress() public constant returns (address) {
	    return address(ecMath);
	}
	
	function ECMath_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = ECMath_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function ECMath_ChangeAddress(address ecMathAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//assert(ECMath_GetCodeSize() == 0);
		
		ecMath = ECMath(ecMathAddr);
		emit ContractAddressChanged("ECMath", ecMathAddr);
	}
	
	modifier requireECMath {
	    require(ECMath_GetCodeSize() > 0);
	    _;
	}
	
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ecMathAddr) public {
	    ECMath_ChangeAddress(ecMathAddr);
	}
}

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

library BulletproofStruct {
	//Structure for VerifyBulletproof() arguments
	struct Data {
		uint256[] V;
		uint256[2] A;
		uint256[2] S;
		uint256[2] T1;
		uint256[2] T2;
		uint256 taux;
		uint256 mu;
		uint256[] L;
		uint256[] R;
		uint256 a;
		uint256 b;
		uint256 t;
		uint256 N;
	}	

	//Creates Bullet Proof struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data[] args)
	{
		//Check input length, need at least 1 argument - assuming all variable arrays are zero length and only store the size
		require(argsSerialized.length >= 1);
		
		//Deserialize
		uint256 i;
		uint256 proof;
		uint256 index;
		uint256 length;
		
		//Get proof count
		length = argsSerialized[0];
		args = new Data[](length);
		
		index = 1;
		for (proof = 0; proof < args.length; proof++) {
		    //Initialize V, L, and R arrays
		    length = argsSerialized[index];
		    if (length > 0) args[proof].V = new uint256[](length);
		    
            length = argsSerialized[index+1];
    		if (length > 0) args[proof].L = new uint256[](length);
    		
    		length = argsSerialized[index+2];
    		if (length > 0) args[proof].R = new uint256[](length);
    		
    		//Check array length again
    		require(argsSerialized.length >= (index + 17 +
    		                                    args[proof].V.length +
    		                                    args[proof].L.length +
    		                                    args[proof].R.length));
    		index += 3;
		    
		    //Get V array
		    length = args[proof].V.length;
		    for (i = 0; i < length; i++) {
		        args[proof].V[i] = argsSerialized[index+i];
		    }
		    index += length;
		    
		    //Get A, S, T1, taux, an mu
    		args[proof].A = [argsSerialized[index], argsSerialized[index+1]];
    		args[proof].S = [argsSerialized[index+2], argsSerialized[index+3]];
    		args[proof].T1 = [argsSerialized[index+4], argsSerialized[index+5]];
    		args[proof].T2 = [argsSerialized[index+6], argsSerialized[index+7]];
    		args[proof].taux = argsSerialized[index+8];
    		args[proof].mu = argsSerialized[index+9];
    		index += 10;
    		
    		//Get L Array
    		length = args[proof].L.length;
    		for (i = 0; i < length; i++) {
    			args[proof].L[i] = argsSerialized[index+i];
    		}
    		index += length;
    		
    		length = args[proof].R.length;
    		for (i = 0; i < length; i++) {
    			args[proof].R[i] = argsSerialized[index+i];
    		}
    		index += length;
    		
    		args[proof].a = argsSerialized[index];
    		args[proof].b = argsSerialized[index+1];
    		args[proof].t = argsSerialized[index+2];
    		args[proof].N = argsSerialized[index+3];
    		index += 4;
		}
	}
	
	//Decomposes Bulletproof struct into uint256 array
	function Serialize(Data[] args)
		internal pure returns (uint256[] argsSerialized)
	{
	    //Calculate total args length
	    uint256 proof;
	    uint256 length = 1;
	    for (proof = 0; proof < args.length; proof++) {
	        length += 17 + args[proof].V.length + args[proof].L.length + args[proof].R.length;
	    }
		argsSerialized = new uint256[](length);
		
		//Store proof count
		argsSerialized[0] = args.length;
		
		//Assemble proofs
		uint256 i;
	    uint256 index = 1;
		for (proof = 0; proof < args.length; proof++) {
		    //Store V, L, and R sizes
		    argsSerialized[index] = args[proof].V.length;
		    argsSerialized[index+1] = args[proof].L.length;
		    argsSerialized[index+2] = args[proof].R.length;
		    index += 3;
		    
		    //Store V[]
		    length = args[proof].V.length;
		    for (i = 0; i < length; i++) {
		        argsSerialized[index+i] = args[proof].V[i];
		    }
		    index += length;
		    
		    //Store A, S, T1, T2, taux, mu, len(L), and len(R)
		    argsSerialized[index] = args[proof].A[0];
    		argsSerialized[index+1] = args[proof].A[1];
    		argsSerialized[index+2] = args[proof].S[0];
    		argsSerialized[index+3] = args[proof].S[1];
    		argsSerialized[index+4] = args[proof].T1[0];
    		argsSerialized[index+5] = args[proof].T1[1];
    		argsSerialized[index+6] = args[proof].T2[0];
    		argsSerialized[index+7] = args[proof].T2[1];
    		argsSerialized[index+8] = args[proof].taux;
    		argsSerialized[index+9] = args[proof].mu;
    		index += 10;
    		
    		//Store L[]
    		length = args[proof].L.length;
		    for (i = 0; i < length; i++) {
		        argsSerialized[index+i] = args[proof].L[i];
		    }
		    index += length;

    		//Store R[]
    		length = args[proof].R.length;
		    for (i = 0; i < length; i++) {
		        argsSerialized[index+i] = args[proof].R[i];
		    }
		    index += length;
		    
		    //Store a, b, t, and N
		    argsSerialized[index] = args[proof].a;
		    argsSerialized[index+1] = args[proof].b;
		    argsSerialized[index+2] = args[proof].t;
		    argsSerialized[index+3] = args[proof].N;
		    index += 4;
		}
	}
	
	function EchoTest(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return Serialize(Deserialize(argsSerialized));
	}
}

