// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "crypto/common.h"

#include "crypto/progpow/ethash.h"
#include "crypto/progpow/ethash.hpp"
#include "crypto/progpow/keccak.h"
#include "crypto/progpow/endianness.hpp"
#include "streams.h"


//get block header progpow hash based header, nonce and mix hash
uint256 getBlockHeaderProgPowHash(const CBlockHeader *pblock)
{
    uint64_t nonce = (pblock->nNonce).GetUint64(3);

    // I = the block header minus nonce and solution.
    // also uses CEquihashInput as custom header
    CEquihashInput I{*pblock};
    // I||V  nonce part should be zeroed
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    //the nonce should be zeroed
    memset((unsigned char*)&ss[108], 0, 32);
    ethash::hash256 header_hash = ethash_keccak256((unsigned char*)&ss[0], 140);

    ethash::hash256 mix;
    //solution starts with  32 bytes mix hash.
    const unsigned char *p = &*(pblock->nSolution.begin());
    memcpy(mix.bytes, &p[0], 32);

    /*
    //used to get block header hash for ProgPoW genesis block creation
    uint256 header_v;
    memcpy(header_v.begin(), header_hash.bytes, 32);
    std::cout << "getBlockHeaderProgPowHash header= " << header_v.GetHex().c_str() << "\n";
    memcpy(header_v.begin(), mix.bytes, 32);
    std::cout << "getBlockHeaderProgPowHash mix= " << header_v.GetHex().c_str() << "\n";
    std::cout << "getBlockHeaderProgPowHash nonce= " << nonce << "\n";
    */
    
    //ethash::progpow
    ethash::hash256 
        ret = ethash::verify_final_progpow_hash(header_hash, mix, nonce);

    uint256 r;
    //memcpy(r.begin(), ret.bytes, 32);
    //ethash hash is always consider as big endian. uint256 is little endian.
    uint8_t *pp = r.begin();
    for (int i = 0 ; i < 32; i++) {
        pp[i] = ret.bytes[31-i];
    }
    return r;
}

uint256 CBlockHeader::GetHash(const Consensus::Params& params) const
{
    int version;

    //after progpow fork and has the solution.
    if ((nHeight >= (uint32_t)params.ProgForkHeight) && 
                            (this->nSolution.size() > 0)){
        return getBlockHeaderProgPowHash(this);
    }

    if (nHeight >= (uint32_t)params.BCIHeight) {
        version = PROTOCOL_VERSION;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
    }
    CHashWriter writer(SER_GETHASH, version);
    ::Serialize(writer, *this);
    return writer.GetHash();
}

uint256 CBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nHeight=%u, nTime=%u, nBits=%08x, nNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nHeight, nTime, nBits, nNonce.GetHex(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
