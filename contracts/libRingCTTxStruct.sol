pragma solidity ^0.4.22;

import "./libUTXO.sol";

library RingCTTxStruct {
    //Structure for ValidateRingCTTx() arguments
    struct Data {
		address redeem_eth_address;
		uint256 redeem_eth_value;
		UTXO.Input[] input_tx;
		UTXO.Output[] output_tx;
		uint256[] I;
		uint256[] signature;
	}
    
    //Creates RingCT Tx Args struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data args)
	{
		//Check input length, need at least 8 arguments - assuming all arrays are zero length and only store the size
		require(argsSerialized.length >= 6);
		
		//Deserialize
		uint256 i;
		uint256 index;
		uint256 length;
		args.redeem_eth_address = address(argsSerialized[0]);
		args.redeem_eth_value = argsSerialized[1];
		
		//Initialize Arrays
		length = argsSerialized[2];
		if (length > 0) args.input_tx = new UTXO.Input[](length);
		
		length = argsSerialized[3];
		if (length > 0) args.output_tx = new UTXO.Output[](length);
		
		length = argsSerialized[4];
		if (length > 0) args.I = new uint256[](length);
		
		length = argsSerialized[5];
		if (length > 0) args.signature = new uint256[](length);
		
		//Check input length again
		//In the first case, all args are provided explicitly
		length = 6 + args.input_tx.length*4 + args.output_tx.length*9 + args.I.length + args.signature.length;
		index = 6;
		if (argsSerialized.length >= length) {
			//Assemble the rest of args
			for (i = 0; i < args.input_tx.length; i++) {
				args.input_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
				args.input_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
				index = index + 4;
			}
		}
		else {
			//In the 2nd case, input_tx values are implicit.  This makes sense, because usually these will be supplied by the contract
			//Subtract of 2 for each args.input_tx.value[i]
			length -= args.input_tx.length*2;
			if (argsSerialized.length >= length) {
				//Assemble the rest of args (with implicit args.input_tx.value[i])
				index = 6;
				for (i = 0; i < args.input_tx.length; i++) {
					args.input_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
					//No check for args.input_tx.value[i]
					index = index + 2;
				}
			}
			else {
				revert(); //Not enough arguments
			}
		}
		
		//In either case, all other arguments must be supplied explicitly
		for (i = 0; i < args.output_tx.length; i++) {
			args.output_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
			args.output_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
			args.output_tx[i].dhe_point = [argsSerialized[index+4], argsSerialized[index+5]];
			args.output_tx[i].encrypted_data = [argsSerialized[index+6], argsSerialized[index+7], argsSerialized[index+8]];
			index = index + 9;
		}
		
		for (i = 0; i < args.I.length; i++) {
			args.I[i] = argsSerialized[index+i];
		}
		index = index + args.I.length;
		
		for (i = 0; i < args.signature.length; i++) {
			args.signature[i] = argsSerialized[index+i];
		}
	}
	
	//Decomposes Ring CT Tx Args struct into uint256 array
	function Serialize(Data args)
		internal pure returns (uint256[] argsSerialized)
	{
		argsSerialized = new uint256[](6 + args.input_tx.length*4 + args.output_tx.length*9 + args.I.length + args.signature.length);
		
		argsSerialized[0] = uint256(args.redeem_eth_address);
		argsSerialized[1] = args.redeem_eth_value;
		argsSerialized[2] = args.input_tx.length;
		argsSerialized[3] = args.output_tx.length;
		argsSerialized[4] = args.I.length;
		argsSerialized[5] = args.signature.length;
		
		uint256 i;
		uint256 index = 6;
		for (i = 0; i < args.input_tx.length; i++) {
			argsSerialized[index] = args.input_tx[i].pub_key[0];
			argsSerialized[index+1] = args.input_tx[i].pub_key[1];
			argsSerialized[index+2] = args.input_tx[i].value[0];
			argsSerialized[index+3] = args.input_tx[i].value[1];
			index = index + 4;
		}
		
		for (i = 0; i < args.output_tx.length; i++) {
			argsSerialized[index] = args.output_tx[i].pub_key[0];
			argsSerialized[index+1] = args.output_tx[i].pub_key[1];
			argsSerialized[index+2] = args.output_tx[i].value[0];
			argsSerialized[index+3] = args.output_tx[i].value[1];
			argsSerialized[index+4] = args.output_tx[i].dhe_point[0];
			argsSerialized[index+5] = args.output_tx[i].dhe_point[1];
			argsSerialized[index+6] = args.output_tx[i].encrypted_data[0];
			argsSerialized[index+7] = args.output_tx[i].encrypted_data[1];
			argsSerialized[index+8] = args.output_tx[i].encrypted_data[2];
			index = index + 9;
		}
		
		for (i = 0; i < args.I.length; i++) {
		    argsSerialized[index+i] = args.I[i];
		}
		index = index + args.I.length;
		
		for (i = 0; i < args.signature.length; i++) {
		    argsSerialized[index+i] = args.signature[i];
		}
	}
	
	function EchoTest(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return Serialize(Deserialize(argsSerialized));
	}
}