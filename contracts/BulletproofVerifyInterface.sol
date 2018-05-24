pragma solidity ^0.4.22;

import "./Debuggable.sol";
import "./libBulletproofStruct.sol";

//Contract interface for calling ECMath contract stored else-where on chain
contract BulletproofVerify {
    //Verify Bulletproof(s), can do multiple commitements and multiple proofs at once
    //This function's arguments are serialized into uint256[] array so it can be called externally w/o abi encoding
	function VerifyBulletproof(uint256[] argsSerialized) public view returns (bool);
}

//Example Interface Contract
//This contract provieds useful functions for utilizing a ECMath contract stored else-where on chain
contract BulletproofVerifyInterface is Debuggable {
    //Prerequisite Contract(s)
	BulletproofVerify bpVerify;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function BulletproofVerify_GetAddress() public constant returns (address) {
	    return address(bpVerify);
	}
	
	function BulletproofVerify_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = BulletproofVerify_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function BulletproofVerify_ChangeAddress(address bpVerifyAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//assert(BulletproofVerify_GetCodeSize() == 0);
		
		bpVerify = BulletproofVerify(bpVerifyAddr);
		emit ContractAddressChanged("BulletproofVerify", bpVerifyAddr);
	}
	
	modifier requireBulletproofVerify {
	    require(BulletproofVerify_GetCodeSize() > 0);
	    _;
	}
	
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address bpVerifyAddr) public {
	    BulletproofVerify_ChangeAddress(bpVerifyAddr);
	}
}