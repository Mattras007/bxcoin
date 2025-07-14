#include <iostream>
#include <string>
#include <vector>

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "crypto/sha256.h"
#include "consensus/merkle.h"
#include "util/strencodings.h"
#include "arith_uint256.h"
#include "uint256.h"
#include "script/script.h"

struct NetworkParams {
    std::string name;
    uint32_t nTime;
    uint32_t nBits;
    std::string pszTimestamp;
    std::string pubKeyHex;
};

CBlock CreateGenesisBlock(const NetworkParams& net) {
    const CScript genesisOutputScript = CScript() << ParseHex(net.pubKeyHex) << OP_CHECKSIG;

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4)
        << std::vector<unsigned char>((const unsigned char*)net.pszTimestamp.c_str(),
            (const unsigned char*)net.pszTimestamp.c_str() + net.pszTimestamp.size());
    txNew.vout[0].nValue = 50 * COIN;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = net.nTime;
    genesis.nBits    = net.nBits;
    genesis.nNonce   = 0;
    genesis.nVersion = 1;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    return genesis;
}

int main() {
    // Mainnet uses real Bitcoin difficulty to mine legit genesis.
    // Testnet, Regtest, Diginet set to easy difficulty so they mine instantly.
    std::vector<NetworkParams> networks = {
        { "Mainnet", 1231006505, 0x1d00ffff, "Turn around, The Kingdom of Heaven is Near",
          "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f" },
        { "Testnet", 1296688602, 0x207fffff, "Testnet Genesis Block",
          "0437cd4c93b2ef408d9beaa3ad49ce9a2e7ee9c28f02a8bf44aa0d970f4db55c9f3c582b83d32e6e9d68f7b5fa1b07c6b9a557a7533b3a8c104dff0d7f39e7d1b9" },
        { "Regtest", 1296688602, 0x207fffff, "Regtest Genesis Block",
          "0437cd4c93b2ef408d9beaa3ad49ce9a2e7ee9c28f02a8bf44aa0d970f4db55c9f3c582b83d32e6e9d68f7b5fa1b07c6b9a557a7533b3a8c104dff0d7f39e7d1b9" },
        { "Diginet", 1700000000, 0x207fffff, "Diginet Launch - Prepare for Flight",
          "0437cd4c93b2ef408d9beaa3ad49ce9a2e7ee9c28f02a8bf44aa0d970f4db55c9f3c582b83d32e6e9d68f7b5fa1b07c6b9a557a7533b3a8c104dff0d7f39e7d1b9" }
    };

    for (auto& net : networks) {
        std::cout << "Mining genesis for: " << net.name << std::endl;
        CBlock genesis = CreateGenesisBlock(net);

        arith_uint256 target;
        target.SetCompact(genesis.nBits);

        while (true) {
            uint256 hash = genesis.GetHash();
            if (UintToArith256(hash) <= target) break;
            if (++genesis.nNonce == 0) ++genesis.nTime;
        }

        std::cout << "Genesis Block Mined!" << std::endl;
        std::cout << "Hash: " << genesis.GetHash().ToString() << std::endl;
        std::cout << "Merkle Root: " << genesis.hashMerkleRoot.ToString() << std::endl;
        std::cout << "Time: " << genesis.nTime << std::endl;
        std::cout << "Nonce: " << genesis.nNonce << std::endl;
        std::cout << "Bits: 0x" << std::hex << genesis.nBits << std::dec << std::endl;
        std::cout << "----------------------------------------" << std::endl;
    }

    return 0;
}

