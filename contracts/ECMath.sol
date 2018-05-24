pragma solidity ^0.4.22;

import "./Debuggable.sol";

contract ECMath is Debuggable {
	//alt_bn128 constants
	uint256[2] private G1;
	uint256[2] private H;
	uint256[2] private Inf;
	uint256[] private Gi;
	uint256[] private Hi;
	uint256 constant private NCurve = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
	uint256 constant private PCurve = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

	//Used for Point Compression/Decompression
	uint256 constant private ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000;
	uint256 constant private a = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52; // (p+1)/4
	
	constructor(uint256 N) public {
        G1 = [uint256(1), 2];
    	H = HashToPoint(G1);
		
		Inf = [uint256(0), 0];
		
		GenerateBasePointVectors(N);
	}
	
	//Base EC Parameters
	function GetG1() public view returns (uint256[2]) { return G1; }
	function GetH() public view returns (uint256[2]) { return H; }
	function GetInfinity() public view returns (uint256[2]) { return Inf; }
	function GetNCurve() public pure returns (uint256) { return NCurve; }
	function GetPCurve() public pure returns (uint256) { return PCurve; }
	
	function GetGiHi(uint256 N)
		public constant returns (uint256[], uint256[])
	{
	    //Base points must have been generated first
	    uint256 len = 2*N;
        require(Gi.length >= len);
        
        //If length matches exactly then the whole vector can be sent
        //If length = 0 is requested, send the whole vector as well
        if (len == 0 || Gi.length == len) {
            return (Gi, Hi);
        }
        //Else, slice vector
        else {
            uint256[] memory Gi_out = new uint256[](len);
            uint256[] memory Hi_out = new uint256[](len);
            uint256 i;
            for (i = 0; i < len; i++) {
                Gi_out[i] = Gi[i];
                Hi_out[i] = Hi[i];
            }
            
            return (Gi_out, Hi_out);
        }
	}
	
	function GetGiHiLength() public view returns (uint256) {
	    return (Gi.length / 2);
	}
	
	//Generate Gi and Hi points.
	//Each is created from HashToPoint of another generator point:
	//G1 -> H -> Gi[0] -> Hi[0] -> Gi[1] -> Hi[1] -> ...
	function GenerateBasePointVectors(uint256 N) ownerOnly public {
	    uint256 existing = (Gi.length / 2);
	    if (N > existing) {
	        uint256[] memory Gi_new = new uint256[](N*2);
	        uint256[] memory Hi_new = new uint256[](N*2);
	        
	        uint256 i;
	        //Copy existing base points
	        for (i = 0; i < Gi.length; i++) {
	            Gi_new[i] = Gi[i];
	            Hi_new[i] = Hi[i];
	        }
	        
	        //Create new points, store starting point in temp
	        uint256 index;
	        uint256[2] memory temp;
	        if (existing == 0) {
	            temp = H;
	        }
	        else {
	            index = Hi.length-2;
	            temp = [Hi[index], Hi[index+1]];
	        }
	        
	        for (i = existing; i < N; i++) {
	            index = 2*i;
	            temp = HashToPoint(temp);
	            (Gi_new[index], Gi_new[index+1]) = (temp[0], temp[1]);
	            
	            temp = HashToPoint(temp);
	            (Hi_new[index], Hi_new[index+1]) = (temp[0], temp[1]);
	        }
	        
	        Gi = Gi_new;
	        Hi = Hi_new;
	    }
	}
	
	//Base EC Functions
	function Negate(uint256[2] p1)
		public pure returns (uint256[2] p2)
	{	
		p2[0] = p1[0];
		p2[1] = PCurve - (p1[1] % PCurve);
	}
	
	function Equals(uint256[2] p1, uint256[2] p2)
		public pure returns (bool)
	{
		return ((p1[0] == p2[0]) && (p1[1] == p2[1]));
	}
	
	function Add(uint256[2] p0, uint256[2] p1)
    	public constant returns (uint256[2] p2)
	{
    	assembly {
        	//Get Free Memory Pointer
        	let p := mload(0x40)
       	 
        	//Store Data for ECAdd Call
        	mstore(p, mload(p0))
        	mstore(add(p, 0x20), mload(add(p0, 0x20)))
        	mstore(add(p, 0x40), mload(p1))
        	mstore(add(p, 0x60), mload(add(p1, 0x20)))
       	 
        	//Call ECAdd
        	let success := call(sub(gas, 2000), 0x06, 0, p, 0x80, p, 0x40)
       	 
        	// Use "invalid" to make gas estimation work
         	switch success case 0 { revert(p, 0x80) }
        	 
         	//Store Return Data
         	mstore(p2, mload(p))
         	mstore(add(p2, 0x20), mload(add(p,0x20)))
    	}
	}
    
	function Subtract(uint256[2] p0, uint256[2] p1)
    	public constant returns (uint256[2] p2)
	{
		return Add(p0, Negate(p1));
	}
	
	function Multiply(uint256[2] p0, uint256 s)
    	public constant returns (uint256[2] p1)
	{
    	assembly {
        	//Get Free Memory Pointer
        	let p := mload(0x40)
       	 
        	//Store Data for ECMul Call
        	mstore(p, mload(p0))
        	mstore(add(p, 0x20), mload(add(p0, 0x20)))
        	mstore(add(p, 0x40), s)
       	 
        	//Call ECAdd
        	let success := call(sub(gas, 2000), 0x07, 0, p, 0x60, p, 0x40)
       	 
        	// Use "invalid" to make gas estimation work
         	switch success case 0 { revert(p, 0x80) }
        	 
         	//Store Return Data
         	mstore(p1, mload(p))
         	mstore(add(p1, 0x20), mload(add(p,0x20)))
    	}
	}
    
    //Shortcut Functions
    function MultiplyG1(uint256 s)
        public constant returns (uint256[2] p0)
    {
        return Multiply(G1, s);
    }
    
    function MultiplyH(uint256 s)
        public constant returns (uint256[2] p0)
    {
        return Multiply(H, s);
    }
    
    //Returns p0 = p_add + s*p_mul
    function AddMultiply(uint256[2] p_add, uint256[2] p_mul, uint256 s)
        public constant returns (uint256[2] p0)
    {
        return Add(p_add, Multiply(p_mul, s));
    }
    
    //Returns p0 = p_add + s*G1    
    function AddMultiplyG1(uint256[2] p_add, uint256 s)
        public constant returns (uint256[2] p0)
    {
        return AddMultiply(p_add, G1, s);
    }
    
    //Returns p0 = p_add + s*H
    function AddMultiplyH(uint256[2] p_add, uint256 s)
        public constant returns (uint256[2] p0)
    {
        return AddMultiply(p_add, H, s);
    }
    
	//Returns p0 = s_G1*G1 + s_H*H
    function CommitG1H(uint256 s_G1, uint256 s_H)
        public constant returns (uint256[2] p0)
    {
        return Add(MultiplyG1(s_G1), MultiplyH(s_H));
    }
	
	//Vector Functions
	function VectorScale(uint256[] X, uint256 s)
		public constant returns (uint256[] Z)
	{
		require(X.length > 1);
		require(X.length % 2 == 0);
		
		Z = new uint256[](X.length);
		
		uint256 i;
		uint256[2] memory temp;
		for (i = 0; i < X.length; i += 2) {
			temp = Multiply([X[i], X[i+1]], s);
			(Z[i], Z[i+1]) = (temp[0], temp[1]);
		}
	}
	
	function VectorAdd(uint256[] X, uint256[] Y)
		public constant returns (uint256[] Z)
	{
		require(X.length > 1);
		require(X.length % 2 == 0);
		require(Y.length == X.length);
		
		Z = new uint256[](X.length);
		
		uint256 i;
		uint256[2] memory temp;
		for (i = 0; i < X.length; i += 2) {
			temp = Add([X[i], X[i+1]], [Y[i], Y[i+1]]);
			(Z[i], Z[i+1]) = (temp[0], temp[1]);
		}
	}
	
	function VectorMul(uint256[] X, uint256[] s)
		public constant returns (uint256[] Z)
	{
		require(s.length > 0);
		require(X.length == s.length*2);
		
		Z = new uint256[](X.length);
		
		uint256 i;
		uint256 index;
		uint256[2] memory temp;
		for (i = 0; i < s.length; i++) {
			index = 2*i;
			temp = Multiply([X[index], X[index+1]], s[i]);
			(Z[index], Z[index+1]) = (temp[0], temp[1]);
		}
	}
	
	//Returns s0*P0 + s1*P1 + ... + sk*Pk
    function MultiExp(uint256[] P, uint256[] s, uint256 start, uint256 end)
        public constant returns (uint256[2] Pout)
    {
        require(P.length > 1);
        require(P.length % 2 == 0);
        require(P.length == 2*s.length);
        if (end == 0) end = s.length;
        require(end > start);
        
        //Multiply first point
        uint256 index = 2*start;
        Pout = Multiply([P[index], P[index+1]], s[start]);
        index += 2;
        
        //Multiply the rest of the points
        uint256 i;
        for (i = start+1; i < end; i++) {
            Pout = AddMultiply(Pout, [P[index], P[index+1]], s[i]);
            index += 2;
        }
    }
    
    //Returns Pin + s0*P0 + s1*P1 + ... + sk*Pk
	function AddMultiExp(uint256[2] Pin, uint256[] P, uint256[] s, uint256 start, uint256 end)
        public constant returns (uint256[2] Pout)
    {
		Pout = Add(Pin, MultiExp(P, s, start, end));
	}
    
    //Returns px = x[0]*X[0] + x[1]*X[1] + ... + x[n-1]*X[n-1]
    //    and py = y[0]*Y[0] + y[1]*Y[1] + ... + y[n-1]*Y[n-1]
    function CommitAB(uint256[] X, uint256[] Y, uint256[] x, uint256[] y)
        public constant returns (uint256[2] px, uint256[2] py)
    {
        px = MultiExp(X, x, 0, 0);
        py = MultiExp(Y, y, 0, 0);
    }
    
    //Point Compression and Expansion Functions
	function CompressPoint(uint256[2] Pin)
    	public pure returns (uint256 Pout)
	{
    	//Store x value
    	Pout = Pin[0];
   	 
    	//Determine Sign
    	if ((Pin[1] & 0x1) == 0x1) {
        	Pout |= ECSignMask;
    	}
	}
    
	function EvaluateCurve(uint256 x)
    	public constant returns (uint256 y, bool onCurve)
	{
    	uint256 y_squared = mulmod(x, x, PCurve);
    	y_squared = mulmod(y_squared, x, PCurve);
    	y_squared = addmod(y_squared, 3, PCurve);
   	 
    	uint256 p_local = PCurve;
    	uint256 a_local = a;
   	 
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
    
	function ExpandPoint(uint256 Pin)
    	public constant returns (uint256[2] Pout)
	{
    	//Get x value (mask out sign bit)
    	Pout[0] = Pin & (~ECSignMask);
   	 
    	//Get y value
    	bool onCurve;
    	uint256 y;
    	(y, onCurve) = EvaluateCurve(Pout[0]);
   	 
    	//TODO: Find better failure case for point not on curve
    	if (!onCurve) {
    	    Pout = [uint256(0), 0];
    	}
    	else {
        	//Use Positive Y
        	if ((Pin & ECSignMask) != 0) {
            	if ((y & 0x1) == 0x1) {
                	Pout[1] = y;
            	} else {
                	Pout[1] = PCurve - y;
            	}
        	}
        	//Use Negative Y
        	else {
            	if ((y & 0x1) == 0x1) {
                	Pout[1] = PCurve - y;
            	} else {
                	Pout[1] = y;
            	}
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
        PubKey = Multiply(G1, privatekey);
    }
    
    function GetAddressFromPrivateKey(uint256 privatekey)
        public constant returns (address addr)
    {
        addr = GetAddress(GetPublicKeyFromPrivateKey(privatekey));
    }

    //Return H = keccak256(p)
    function HashOfPoint(uint256[2] point)
        public pure returns (uint256 h)
    {
        h = uint256(keccak256(point[0], point[1]));
    }
    
	//Return H = alt_bn128 evaluated at keccak256(p)
    function HashToPoint(uint256[2] p)
        public constant returns (uint256[2] h)
    {
        h[0] = HashOfPoint(p) % PCurve;
        
        bool onCurve = false;
        while(!onCurve) {
            (h[1], onCurve) = EvaluateCurve(h[0]);
            
			if (!onCurve) {
				h[0] = addmod(h[0], 1, PCurve);
			}
        }
    }
}