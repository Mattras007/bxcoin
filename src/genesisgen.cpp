#include <iostream>
#include <stdint.h>
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "crypto/sha256.h"
#include "consensus/merkle.h"
#include "util/strencodings.h"
#include "arith_uint256.h"
#include "uint256.h"

uint256 hashGenesisBlock;
uint256 genesisMerkleRoot;

int main() {
    const char* pszTimestamp = "Turn around, the kinddom is near"; // Any custom message
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = 50 * COIN;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = 1720339200; // Example: 07/07/2024 00:00:00 UTC, adjust if you want
    genesis.nBits    = 0x1e0ffff0; // Standard for altcoins
    genesis.nNonce   = 0;
    genesis.nVersion = 1;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    genesisMerkleRoot = genesis.hashMerkleRoot;

    arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
    while (true) {
        hashGenesisBlock = genesis.GetHash();
        if (UintToArith256(hashGenesisBlock) <= hashTarget)
            break;
        if (++genesis.nNonce == 0)
            ++genesis.nTime;
    }

    std::cout << "Genesis Block Found!" << std::endl;
    std::cout << "Hash: " << hashGenesisBlock.ToString() << std::endl;
    std::cout << "Merkle Root: " << genesisMerkleRoot.ToString() << std::endl;
    std::cout << "Time: " << genesis.nTime << std::endl;
    std::cout << "Nonce: " << genesis.nNonce << std::endl;
    std::cout << "Bits: " << std::hex << genesis.nBits << std::dec << std::endl;

    return 0;
}

