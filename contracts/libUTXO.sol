pragma solidity ^0.4.24;

library UTXO {
    //Represents an input unspent transaction output (candidate for spending)
    struct Input {
        uint256[2] pub_key;
        uint256[2] value;
    }
    
    //Represents an output unspent transaction output (new stealth transaction output)
    struct Output {
        uint256[2] pub_key;
        uint256[2] value;
        uint256[2] dhe_point;
        uint256[3] encrypted_data;
    }
}