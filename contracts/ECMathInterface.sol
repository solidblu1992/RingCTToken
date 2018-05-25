pragma solidity ^0.4.24;

import "./Debuggable.sol";

//Contract interface for calling ECMath contract stored else-where on chain
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

//Example Interface Contract
//This contract provieds useful functions for utilizing a ECMath contract stored else-where on chain
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