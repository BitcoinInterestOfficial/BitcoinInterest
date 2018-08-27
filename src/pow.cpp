// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "crypto/equihash.h"
#include "crypto/progpow/ethash.h"
#include "crypto/progpow/ethash.hpp"
#include "crypto/progpow/keccak.h"
#include "crypto/progpow/endianness.hpp"
#include "primitives/block.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    int nHeight = pindexLast->nHeight + 1;
    bool postfork = nHeight >= params.BCIHeight;
    unsigned int nProofOfWorkLimit = UintToArith256(params.PowLimit(postfork)).GetCompact();

    if (postfork == false) {
        return BitcoinGetNextWorkRequired(pindexLast, pblock, params);
    }
    else if (nHeight < params.BCIHeight + params.BCIPremineWindow+10) {
        return nProofOfWorkLimit;
    }
    else if (nHeight < params.BCIHeight + params.BCIPremineWindow + params.nPowAveragingWindow){
        return UintToArith256(params.powLimitStart).GetCompact();
    }
    
    const CBlockIndex* pindexFirst = pindexLast;
    arith_uint256 bnTot {0};
    for (int i = 0; pindexFirst && i < params.nPowAveragingWindow; i++) {
        arith_uint256 bnTmp;
        bnTmp.SetCompact(pindexFirst->nBits);
        bnTot += bnTmp;
        pindexFirst = pindexFirst->pprev;
    }
    
    if (pindexFirst == NULL)
        return nProofOfWorkLimit;
    
    arith_uint256 bnAvg {bnTot / params.nPowAveragingWindow};
    

    return CalculateNextWorkRequired(bnAvg, pindexLast->GetMedianTimePast(), pindexFirst->GetMedianTimePast(), params);
}

unsigned int CalculateNextWorkRequired(arith_uint256 bnAvg, int64_t nLastBlockTime, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    
    // Limit adjustment
    int64_t nActualTimespan = nLastBlockTime - nFirstBlockTime;
    
    if (nActualTimespan < params.MinActualTimespan())
        nActualTimespan = params.MinActualTimespan();
    if (nActualTimespan > params.MaxActualTimespan())
        nActualTimespan = params.MaxActualTimespan();

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.PowLimit(true));
    arith_uint256 bnNew {bnAvg};
    bnNew /= params.AveragingWindowTimespan();
    bnNew *= nActualTimespan;
    
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}


// Deprecated for Bitcoin Interest
unsigned int BitcoinGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.PowLimit(false)).GetCompact();
    
    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return BitcoinCalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}


// Depricated for Bitcoin Interest
unsigned int BitcoinCalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;
    
    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespanLegacy/4)
        nActualTimespan = params.nPowTargetTimespanLegacy/4;
    if (nActualTimespan > params.nPowTargetTimespanLegacy*4)
        nActualTimespan = params.nPowTargetTimespanLegacy*4;
    
    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.PowLimit(false));
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespanLegacy;
    
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;
    
    return bnNew.GetCompact();
}

bool CheckProgPow (const CBlockHeader *pblock, const CChainParams& params)
{
    //progpow nonce is 8 bytes, located the (24-32) of 32 bytes nonce 
    //little endian
    uint64_t nonce = (pblock->nNonce).GetUint64(3);

    uint32_t epoch = ethash::get_epoch_number(pblock->nHeight);
    ethash_epoch_context epoch_ctx = ethash::get_global_epoch_context(epoch);
    epoch_ctx.block_number = pblock->nHeight;
    
    // I = the block header minus nonce and solution.
    // also uses CEquihashInput as custom header
    CEquihashInput I{*pblock};
    // I||V 
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    //nonce part should be zeroed
    memset((unsigned char*)&ss[108], 0, 32); 
    ethash::hash256 header_hash = ethash_keccak256((unsigned char*)&ss[0], 140);

    ethash::hash256 mix;
    //nSolution is 32 bytes mix hash.
    const unsigned char *p = &*(pblock->nSolution.begin());
    memcpy(mix.bytes, &p[0], 32);

    ethash::hash256 target;
    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
    //memcpy(target.bytes, ArithToUint256(hashTarget).begin(), 32);
    //endian conversion. ethash hash is considered as big endian.
    uint8_t *hashTarget_p = ArithToUint256(hashTarget).begin(); 
    for (int i = 0; i < 32; i ++ ) {
        target.bytes[i] = hashTarget_p[31-i];
    }

    //debug:
#if 0
    //show header_hash and nonce
    uint256 header_v, target_v, mixhash_v;
    memcpy(header_v.begin(), header_hash.bytes, 32);
    memcpy(target_v.begin(), target.bytes, 32);
    memcpy(mixhash_v.begin(), mix.bytes, 32);
    error("CheckProgPow: input values: height %d  epoch %d  header %s  nonce %lx  NONCE_UINT64_T %ld  target %s  mixhash %s\n", pblock->nHeight, epoch, header_v.GetHex().c_str(), nonce, nonce, target_v.GetHex().c_str(), mixhash_v.GetHex().c_str());
    
    /*
    // ENABLE TO TEST PROGPOW
    //run progpow
    ethash::result ret = ethash::progpow(epoch_ctx, header_hash, nonce);
    uint256 final_hash, mix_hash;
    memcpy(final_hash.begin(), ret.final_hash.bytes, 32);
    memcpy(mix_hash.begin(), ret.mix_hash.bytes, 32);
    error("CheckProgPow RUN PROGPOW: progpow hash results. final_hash %s, mix_hash %s\n",
          final_hash.GetHex().c_str(), mix_hash.GetHex().c_str());
    */
#endif

    if (ethash::verify_progpow(epoch_ctx, header_hash,
                               mix, nonce, target)) {
        return true;
    } else {
        return error("CheckProgPow(): verify_progpow failed");
    }
 
}

bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams& params)
{
    unsigned int n = params.EquihashN();
    unsigned int k = params.EquihashK();

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);
    if (!isValid)
        return error("CheckEquihashSolution(): invalid solution");

    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, bool postfork, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.PowLimit(postfork))) 
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget) {
        return false;
    }

    return true;
}
