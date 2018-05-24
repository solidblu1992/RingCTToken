pragma solidity ^0.4.22;

import "./Debuggable.sol";
import "./libBorromeanRangeProofStruct.sol";
import "./libRingCTTxStruct.sol";

contract RingCTTxVerify {    
    //Serialized version of ValidateRingCTTx.  This version does not use structs so that it can be called publicly.
	function ValidateRingCTTx(uint256[] argsSerialized) public view returns (bool);
    
    //Serialized version of VerifyBorromeanRangeProof.  This version does not use structs so that it can be called publicly.
	function VerifyBorromeanRangeProof(uint256[] argsSerialized) public view returns (bool);
	
    //Utility Functions
	function HashSendMsg(uint256[] output_pub_keys, uint256[] output_values, uint256[] output_dhe_points, uint256[] output_encrypted_data)
							public pure returns (uint256 msgHash);		

	function HashWithdrawMsg(address ethAddress, uint256 value,
								uint256[] output_pub_keys, uint256[] output_values, uint256[] output_dhe_points, uint256[] output_encrypted_data)
								public pure returns (uint256 msgHash);
}

//Example Interface Contract
//This contract provieds useful functions for utilizing a MLSAGVerify contract stored else-where on chain
contract RingCTTxVerifyInterface is Debuggable {
    //Prerequisite Contract(s)
	RingCTTxVerify ringcttxverify;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function RingCTTxVerify_GetAddress() public constant returns (address) {
		return address(ringcttxverify);
	}
	
	function RingCTTxVerify_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = RingCTTxVerify_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function RingCTTxVerify_ChangeAddress(address ringCTTxVerifyAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//require(RingCTTxVerify_GetCodeSize() == 0);
		
		ringcttxverify = RingCTTxVerify(ringCTTxVerifyAddr);
		emit ContractAddressChanged("RingCTTxVerify", ringCTTxVerifyAddr);
	}
	
	modifier requireRingCTTxVerify {
	    require(RingCTTxVerify_GetCodeSize() > 0);
	    _;
	}

	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ringCTTxVerifyAddr) public {
	    RingCTTxVerify_ChangeAddress(ringCTTxVerifyAddr);
	}
}