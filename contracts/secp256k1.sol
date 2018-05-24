pragma solidity ^0.4.24;

import "./Debuggable.sol";

contract secp256k1 is Debuggable {
    uint256 constant private NCurve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant private PCurve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 constant private ACurve = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c; // (p+1)/4
    uint256[3] private G;
    uint256[3] private H;
    uint256[3] private GH;
    uint256[3] private Inf;
    uint256[3] private Zero;
    
    //Digits for windowed multiplication
    uint256[] public G_precompiles;
    
    //Constructor, set generator points
    constructor(uint _w) public {
        G = [uint256(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798),
             uint256(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
             uint256(1)];
             
        H = HashToPoint(G);
        
        GH = Add(G, H);
		
		Inf = [uint256(0), 0, 0];
		Zero = [uint256(1), 1, 0];
		
		G_precompiles = GeneratePrecompiledPoints(G, _w);
    }
    
    function GeneratePrecompiledPoints(uint256[3] P, uint w)
        public pure returns (uint256[] Pout)
    {
        //Window size must be at least 2 bits: 4 pre-computed values
        require(w > 1);
        uint wpow_over_2 = (1 << (w-1));
        uint wpow_over_4 = (1 << (w-2));
        
        uint index = (wpow_over_4)*3;
        uint neg_index = index - 3;
        
        uint256[3] memory P2 = Double(P);
        uint256[3] memory temp;
        Pout = new uint256[](wpow_over_2*3);
        
        for (uint i = 0; i < wpow_over_4; i++) {
            if (i == 0) {
                temp = P;
            }
            else {
                temp = Add([Pout[index-3], Pout[index-2], Pout[index-1]], P2);
            }
            
            (Pout[index], Pout[index+1], Pout[index+2]) = (temp[0], temp[1], temp[2]);
            
            temp = Negate([Pout[index], Pout[index+1], Pout[index+2]]);
            (Pout[neg_index], Pout[neg_index+1], Pout[neg_index+2]) = (temp[0], temp[1], temp[2]);
        
            index += 3;
            neg_index -= 3;
        }
    }
    
    function GetPrecompiledG(uint index)
        public view returns (uint256[3] kG)
    {
        uint i = 3*index;
        require((i+2) <= G_precompiles.length);
        (kG[0], kG[1], kG[2]) = (G_precompiles[i], G_precompiles[i+1], G_precompiles[i+2]);
    }
    
    function GetPrecompiledGLength() public view returns (uint) {
        return (G_precompiles.length / 3);
    }
    
    //Low level functions
	function sNeg(uint256 a) internal pure returns (uint256 out) {
		out = NCurve - (a % NCurve);
	}
	
	function sAdd(uint256 a, uint256 b) internal pure returns (uint256 out) {
		out = addmod(a, b, NCurve);
	}
	
	function sSub(uint256 a, uint256 b) internal pure returns (uint256 out) {
		out = addmod(a, sNeg(b), NCurve);
	}
	
	function sMul(uint256 a, uint256 b) internal pure returns (uint256 out) {
		out = mulmod(a, b, NCurve);
	}
	
	function sSq(uint256 a) internal pure returns (uint256 out) {
		out = mulmod(a, a, NCurve);
	}
	
	function sPow(uint256 a, uint256 p) internal pure returns (uint256 out) {
		out = a;
		for (uint256 i = 1; i < p; i++) {
			out = mulmod(out, a, NCurve);
		}
	}
	
	function sInv(uint256 a) internal pure returns (uint256 out) {
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
    
    //Elliptic Curve Functions
    function Negate(uint256[3] p1)
		public pure returns (uint256[3] p2)
	{	
	    p2[0] = p1[0];
		p2[1] = sNeg(p1[1]);
		p2[2] = p1[2];
	}
	
    function Double(uint256[3] P1) public pure returns (uint256[3] Pout) {
        //Trival Case
        if (P1[2] == 0) {
            return P1;
        }
        
        uint256 W = sMul(sSq(P1[0]), 3);
		uint256 S = sMul(P1[1], P1[2]);
		uint256 B = sMul(sMul(P1[0], P1[1]), S);
		uint256 H1 = sSub(sSq(W), sMul(B, 8));
		uint256 S_sq = sSq(S);
		Pout[0] = sMul(sMul(H1, S), 2);
		Pout[1] = sSub(sMul(sSub(sMul(B, 4), H1), W), sMul(sMul(sSq(P1[1]), S_sq), 8));
		Pout[2] = sMul(sMul(S_sq, S), 8);
    }
    
    function Add(uint256[3] P1, uint256[3] P2) public pure returns (uint256[3] Pout) {
        //Trival Cases
        if ((P1[2] == 0) || (P2[2] == 0)) {
            if (P2[2] == 0) {
                return P1;
            }
            else {
                return P2;
            }
        }
        
        uint256 U = sMul(P2[1], P1[2]);
        uint256 U2 = sMul(P1[1], P2[2]);
        uint256 V = sMul(P2[0], P1[2]);
        uint256 V2 = sMul(P1[0], P2[2]);
        if ((V == V2) && (U == U2)) {
            return Double(P1);
        }
        else if (V == V2) {
            return [uint256(1), 1, 0];
        }
        
        U = sSub(U, U2);
        V = sSub(V, V2);
        uint256 V_sq = sSq(V);
        uint256 V_sq_times_V2 = sMul(V_sq, V2);
        uint256 V_cu = sMul(V_sq, V);
        uint256 W = sMul(P1[2], P2[2]);
        uint256 A = sSub(sSub(sMul(sSq(U), W), V_cu), sMul(V_sq_times_V2, 2));
        Pout[0] = sMul(V, A);
        Pout[1] = sSub(sMul(sSub(V_sq_times_V2, A), U), sMul(V_cu, U2));
        Pout[2] = sMul(V_cu, W);
    }
    
    function Subtract(uint256[3] p0, uint256[3] p1)
    	public pure returns (uint256[3] p2)
	{
		return Add(p0, Negate(p1));
	}
    
    function Multiply(uint256[3] P1, uint256 s) public constant returns (uint256[3] Pout) {
        //Trivial Cases
        if (s == 0) {
            return [uint256(1), 1, 0];
        }
        else if (s == 1) {
            return P1;
        }
        
        //If G, use windowed method
        if (Equals(P1, G)) {
            //Perform multiplication
            uint d = s;
            int dj;
            uint wPow = (1 << )
            while (d > 0) {
                Pout = Double(Pout);
                
                //Calculate dj, perform Add
                if (d % 2 == 1) {
                    dj = d % wPow
                    dj = 
                }
            }
        }
        else {
            if (s % 2 == 0) {
                return Multiply(Double(P1, s / 2));
            }
            else {
                return Add(Multiply(Double(P1, s / 2)));
            }
        }
    }
    
    function Equals(uint256[3] P1, uint256[3] P2) public pure returns (bool) {
        if (sMul(P1[0], P2[2]) == sMul(P2[0], P1[2])) {
            if (sMul(P1[1], P2[2]) == sMul(P2[1], P1[2])) {
                return true;
            }
            else {
                return false;
            }
        }
        else {
            return false;
        }
    }
    
    function Normalize(uint256[3] Pin) public pure returns (uint256[2] Pout) {
        if (Pin[2] == 1) {
            return [Pin[0], Pin[1]];
        }
        
        uint256 z_inv = sInv(Pin[2]);
        Pout = [sMul(Pin[0], z_inv), sMul(Pin[1], z_inv)];
    }
    
    function EvaluateCurve(uint256 x)
    	public constant returns (uint256 y, bool onCurve)
	{
    	uint256 y_squared = mulmod(x, x, PCurve);
    	y_squared = mulmod(y_squared, x, PCurve);
    	y_squared = addmod(y_squared, 7, PCurve);
   	 
    	uint256 p_local = PCurve;
    	uint256 a_local = ACurve;
   	 
    	assembly {
        	//Get Free Memory Pointer
        	let p := mload(0x40)
       	 
        	//Store Data for Big Int Mod Exp Call
        	mstore(p, 0x20)             	//Length of Base
        	mstore(add(p, 0x20), 0x20)  	//Length of Exponent
        	mstore(add(p, 0x40), 0x20)  	//Length of Modulus
        	mstore(add(p, 0x60), y_squared) //Base
        	mstore(add(p, 0x80), a_local)   //Exponent
        	mstore(add(p, 0xA0), p_local)   //Modulus
       	 
        	//Call Big Int Mod Exp
        	let success := call(sub(gas, 2000), 0x05, 0, p, 0xC0, p, 0x20)
       	 
        	// Use "invalid" to make gas estimation work
         	switch success case 0 { revert(p, 0xC0) }
        	 
         	//Store Return Data
         	y := mload(p)
    	}
   	 
    	//Check Answer
    	onCurve = (y_squared == mulmod(y, y, PCurve));
	}
	
	//Shortcut Functions
    function MultiplyG(uint256 s)
        public constant returns (uint256[3] p0)
    {
        return Multiply(G, s);
    }
    
    function MultiplyH(uint256 s)
        public constant returns (uint256[3] p0)
    {
        return Multiply(H, s);
    }
    
    function MulGGasTest(uint256 s)
        public returns (uint256[3] p0)
    {
        return Multiply(G, s);
    }
    
    function AddGasTest(uint256[3] p0, uint256[3] p1)
        public returns (uint256[3] p2)
    {
        return Add(p0, p1);
    }
    
    //Returns p0 = p_add + s*p_mul
    function AddMultiply(uint256[3] p_add, uint256[3] p_mul, uint256 s)
        public constant returns (uint256[3] p0)
    {
        return Add(p_add, Multiply(p_mul, s));
    }
    
    //Returns p0 = p_add + s*G1    
    function AddMultiplyG1(uint256[3] p_add, uint256 s)
        public constant returns (uint256[3] p0)
    {
        return AddMultiply(p_add, G, s);
    }
    
    //Returns p0 = p_add + s*H
    function AddMultiplyH(uint256[3] p_add, uint256 s)
        public constant returns (uint256[3] p0)
    {
        return AddMultiply(p_add, H, s);
    }
    
	//Returns p0 = s_G*G + s_H*H
    function CommitGH(uint256 s_G, uint256 s_H)
        public constant returns (uint256[3] p0)
    {
        //Naive way
        return Add(MultiplyG(s_G), MultiplyH(s_H));
    }
    
    function CommitGH_Shamir(uint256 s_G, uint256 s_H)
        public constant returns (uint256[3] p0)
    {
        //Better way
        if ((s_G % 2) == 0) {
            if ((s_H % 2) == 0) {
                return CommitGH_Shamir(s_G / 2, s_H / 2);
            }
            else {
                return Add(CommitGH_Shamir(s_G / 2, s_H / 2), H);
            }
        }
        else {
            if ((s_H % 2) == 0) {
                return Add(CommitGH_Shamir(s_G / 2, s_H / 2), G);
            }
            else {
                return Add(CommitGH_Shamir(s_G / 2, s_H / 2), GH);
            }
        }
    }
	
    //Address Functions
	function GetAddress(uint256[2] PubKey)
        public pure returns (address addr)
    {
        addr = address( keccak256(PubKey[0], PubKey[1]) );
    }
    
    function GetPublicKeyFromPrivateKey(uint256 privatekey)
        public constant returns (uint256[2] PubKey)
    {
        PubKey = Normalize(Multiply(G, privatekey));
    }
    
    function GetAddressFromPrivateKey(uint256 privatekey)
        public constant returns (address addr)
    {
        addr = GetAddress(GetPublicKeyFromPrivateKey(privatekey));
    }

    //Return H = keccak256(p)
    function HashOfPoint(uint256[3] point)
        public pure returns (uint256 h)
    {
        uint256[2] memory p_normalized = Normalize(point);
        h = uint256(keccak256(p_normalized[0], p_normalized[1]));
    }
    
	//Return H = alt_bn128 evaluated at keccak256(p)
    function HashToPoint(uint256[3] p)
        public constant returns (uint256[3] h)
    {
        h[0] = HashOfPoint(p) % PCurve;
        h[2] = 1;
        
        bool onCurve = false;
        while(!onCurve) {
            (h[1], onCurve) = EvaluateCurve(h[0]);
            
			if (!onCurve) {
				h[0] = addmod(h[0], 1, PCurve);
			}
        }
    }
}