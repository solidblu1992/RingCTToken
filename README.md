# RingCT Token

RingCTToken (https://rinkeby.etherscan.io/address/0x6b3a740668f1e276aa2499027a8eb1cd1c13970b)
- Main Contract for RingCT Token.  All functionality is accessed through this contract.
- The underlying RingCT protocol aims to create a fungible and private token.  This is accomplished through the combination of linkable ring signatures, output stealth addresses, and confidential transactions.  Ring signatures obfuscate information about the sender, stealth address obfuscate information about the receiver(s), and confidential transactions obfuscate the number of tokens sent.
- RingCT Tokens are backed and redeemable 1:1 for ETH.
- Requires an instance of ECMath, RingCTTxVerify, and BulletproofVerify (accessed through calls)
- For more information about the protocol see the paper by [Shen Noether](https://eprint.iacr.org/2015/1098).

BulletproofVerify (https://rinkeby.etherscan.io/address/0xb2980ddcac235bfe66135bc9b990ec1b5ed5ccf5)

- Contract which handle the verifcation of Bullet Proofs.  This is one of two methods for proving that output pedersen commitments are positive.  Proofs can prove multiple commitments at once, and multiple proofs can be verified at once.  This contract is mainly utilzed through the RingCTToken contract via VerifyPCBulletProof().
- Requires an instance of ECMath (accessed through calls)
- For more information about Bullet Proofs, see the paper by [Bootle et all](https://eprint.iacr.org/2017/1066) and [Monero's blog post](https://getmonero.org/2017/12/07/Monero-Compatible-Bulletproofs.html).

RingCTTxVerify (https://rinkeby.etherscan.io/address/0xe126e4614abc9d0ddc7162d857e33c032bda2271)

- Contract which handles the verification of RingCT transactions and Borromean Range Proofs.
- Using Borromean range proofs is a second option for proving that output pedersen commitments are positive.  In some cases this can be more effecient than Bullet Proofs.  This functionality is mainly utilzed through the RingCTToken contract via VerifyPCBorromeanRangeProof().

- The core RingCT transaction signatures are verified by this contract.
- Each RingCT transaction allows input UTXOs (unspent transaction outputs) to be combined and sent to new destination stealth addresses. 
- Optionally a RingCT transaction can choose to reveal a certain portion of tokens and redeem them for ETH.  This ETH can be redeemed to either a specified receiver or offered up as a bounty for publishing the RingCT transaction by publishing a redeem address of "0x0".

- Requires an instance of ECMath, and MLSAGVerify (accessed through calls)

MSLAGVerify (https://rinkeby.etherscan.io/address/0x3f667759450149ea7b3826f97ea2460cfeb413de)
- (M)(L)SAG - (Multi-layered) (Linkable) Spontaneous Anonymous Group signature
- Verifies many kinds of ring signatures (L = linkable / non-linkable, M = Borromean / non-Borromean).
- Mainly used by RingCTTxVerify.  MSAG signatures are used to verify Borromean Range Proofs, while MLSAG signatures are used to verify RingCT transactions.
- Requires and instance of ECMath.

ECMath (https://rinkeby.etherscan.io/address/0x4552c90db760d5380921e18377a41edcff8d100e)

- Allows access to various Elliptic Curve math functions and access to alt_bn_128 precompiled contracts.
- Used by all other contracts.
