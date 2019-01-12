// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "uint256.h"
#include "arith_uint256.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

// For equihash_parameters_acceptable.
#include "crypto/equihash.h"
#include "net.h"
#include "validation.h"
#define equihash_parameters_acceptable(N, K) \
    ((CBlockHeader::HEADER_SIZE + equihash_solution_size(N, K))*MAX_HEADERS_RESULTS < \
     MAX_PROTOCOL_MESSAGE_LENGTH-1000)

#include "base58.h"
#include <assert.h>
#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.nHeight  = 0;
    genesis.nSolution = nSolution;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}



/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const char* pszTimestamp, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));


class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 100000000;
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256S("0x000000e7b1a4eb6b06f2d11f71e629df71fc35b2a7d0f7cfb12d84a2072e70b8");
        consensus.BIP65Height = 0; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 0; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.BCIHeight = 0; // Around 01/22/2018 12:00 UTC
        consensus.BCIPremineWindow = 0;
        consensus.BCIPremineEnforceWhitelist = true;
        consensus.BCICoinTransferAmount = 1851040046271426U;
        consensus.BCICoinTransferHeight = 850;
        consensus.BCILastHeightWithReward = 281665;
        consensus.BitcoinPostforkBlock = uint256S("000000e7b1a4eb6b06f2d11f71e629df71fc35b2a7d0f7cfb12d84a2072e70b8");
        consensus.BitcoinPostforkTime = 0;
        //progpow fork
        consensus.ProgForkHeight = 0;
        consensus.ProgPostforkBlock = uint256S("000004853362fb6250239995594ad39ac6696c5094e332a8e793bfbc4a2f1d46"); //unused
        consensus.ProgPostforkTime = 0; //unused

        consensus.powLimit = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.powLimitStart = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.powLimitProgStart = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000"); //unused
        consensus.powLimitLegacy = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000"); //unused
        consensus.CharityPubKey = "9bdb39cb8fa89a39f8e292ac70213f0bf4817d4f";
        consensus.PreminedPubKey = "9bdb39cb8fa89a39f8e292ac70213f0bf4817d4f";

        //based on https://github.com/BTCGPU/BTCGPU/issues/78
        consensus.nPowAveragingWindow = 30;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32;
        consensus.nPowMaxAdjustUp = 16;

        consensus.nPowTargetTimespanLegacy = 14 * 24 * 60 * 60;; // 10 minutes
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 806; // 80% of 1008 
        consensus.nMinerConfirmationWindow = 1008; // nPowTargetTimespanLegacy / nPowTargetSpacing 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1548979200; // February 1st, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1579046400; // January 15th, 2020 

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1548979200; // February 1st, 2019.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1579046400; // January 15th, 2020. 

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000e7b1a4eb6b06f2d11f71e629df71fc35b2a7d0f7cfb12d84a2072e70b8"); //477890

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStartLegacy[0] = 0xf9;
        pchMessageStartLegacy[1] = 0xbe;
        pchMessageStartLegacy[2] = 0xb4;
        pchMessageStartLegacy[3] = 0xd9;

        pchMessageStart[0] = 0xed;
        pchMessageStart[1] = 0xe4;
        pchMessageStart[2] = 0xfe;
        pchMessageStart[3] = 0x26;
        nDefaultPort = 8334; // different port than Bitcoin
        nBitcoinDefaultPort = 8334;
        nPruneAfterHeight = 100000;
        const size_t N = 80, K = 4; //(80/(4+1)+1)*(1<<4)/8 = 34 is good enough as we want to use just 32 B
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        //headerhash = f576bf15ce9998c32dddf910ca9195796db88b1d40c9afea3c1523e6d22a3276
        const char* pszTimestamp = "how many endians does it take to screw in a progpow? 0400, no wait, 0004";
        genesis = CreateGenesisBlock(1535680000, pszTimestamp,
            uint256S("0xc5bb71e3dbec6a1f000000000000000000000000000000000000000000000000"),
            ParseHex("6ba37f45f721c0496fd5d8b0e4e3cde033ba6b9cc655ba6e35c018506e49632c"), 0x1f00ffff, 1, 13.5 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash(consensus);

        //std::cout << "consensus.hashGenesisBlock " << consensus.hashGenesisBlock.GetHex().c_str() << " <<\n";
        //std::cout << "genesis.hashMerkleRoot     " << genesis.hashMerkleRoot.GetHex().c_str() << " <<\n";

        assert(consensus.hashGenesisBlock == uint256S("00000d74c4f0d40f1bc6c269081440297f72939b13faaec052023e3899f59078"));
        assert(genesis.hashMerkleRoot == uint256S("41c651eff815a1d1d12b0267ea8515b3587ea9267a7ee8878bc588aab4fb4ae1"));


        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("seeder1.bci-server.com", true);
        vSeeds.emplace_back("seeder2.bci-server.com", true);
        vSeeds.emplace_back("seeder3.bci-server.com", true);
        vSeeds.emplace_back("37.16.104.241", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,102);  // prefix: i
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,23);   // prefix: A
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
            }
        };

        chainTxData = ChainTxData{
                // Data as of block 000000000000000000d97e53664d17967bd4ee50b23abb92e54a34eb222d15ae (height 478913).
                1501801925, // * UNIX timestamp of last known number of transactions
                243756039,  // * total number of transactions between genesis and that timestamp
                //   (the tx=... number in the SetBestChain debug.log lines)
                3.1         // * estimated number of transactions per second after that timestamp

        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 100000000;
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 0; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 0; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.BCIHeight = 0;
        consensus.BCIPremineWindow = 0; 
        consensus.BCIPremineEnforceWhitelist = false;
        consensus.BCICoinTransferAmount = 1851040046271426U;
        consensus.BCILastHeightWithReward = 281665;
        consensus.BCICoinTransferHeight = 850;
        consensus.BitcoinPostforkBlock = uint256S("00000000ef93c2d9bac8da61ff11a699a5b815f77a194c567c5de0dbdf0bf28b");
        consensus.BitcoinPostforkTime = 0;
        //progpow fork
        consensus.ProgForkHeight = 0;
        consensus.ProgPostforkBlock = uint256S("000004853362fb6250239995594ad39ac6696c5094e332a8e793bfbc4a2f1d46"); //unused
        consensus.ProgPostforkTime = 0; //unused
        
        consensus.powLimit = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.powLimitStart = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.powLimitProgStart = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000"); //unused
        consensus.powLimitLegacy = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.CharityPubKey = "9bdb39cb8fa89a39f8e292ac70213f0bf4817d4f";
        consensus.PreminedPubKey = "9bdb39cb8fa89a39f8e292ac70213f0bf4817d4f";

        //based on https://github.com/BTCGPU/BTCGPU/issues/78
        consensus.nPowAveragingWindow = 30;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32;
        consensus.nPowMaxAdjustUp = 16;
        
        consensus.nPowTargetTimespanLegacy = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespanLegacy / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000002e9e7b00e1f6dc5123a04aad68dd0f0968d8c7aa45f6640795c37b1"); //1135275

        
        pchMessageStartLegacy[0] = 0x0b;
        pchMessageStartLegacy[1] = 0x11;
        pchMessageStartLegacy[2] = 0x09;
        pchMessageStartLegacy[3] = 0x07;

        pchMessageStart[0] = 0xdd;
        pchMessageStart[1] = 0x74;
        pchMessageStart[2] = 0xe7;
        pchMessageStart[3] = 0x7b;
        nDefaultPort = 18331;
        nBitcoinDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        const size_t N = 80, K = 4; //(80/(4+1)+1)*(1<<4)/8 = 34 is good enough as we want to use just 32 B
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        const char* pszTimestamp = "BCI-TESTNET-GENESIS";
        genesis = CreateGenesisBlock(1535730000, pszTimestamp,
            uint256S("0x63e59b59ca41c608000000000000000000000000000000000000000000000000"), 
            ParseHex("6bdc7abb86565105f593ef3e9ce442f0d1430dfc6c846a34476223ee15034fb5"), 0x1f00ffff, 1, 13.5 * COIN);
        
        consensus.hashGenesisBlock = genesis.GetHash(consensus);
        //std::cout << "consensus.hashGenesisBlock " << consensus.hashGenesisBlock.GetHex().c_str() << " <<\n";
        //std::cout << "genesis.hashMerkleRoot     " << genesis.hashMerkleRoot.GetHex().c_str() << " <<\n";
       
        assert(consensus.hashGenesisBlock == uint256S("0x00002057b3b31636c2b061faf2bab4b49f7eb13a7d01bfbae978f0e33e3b7a07"));
        assert(genesis.hashMerkleRoot == uint256S("0xb917ca598bd6459676df61884f8cba97c03263c32f81cc57b27ceab2cdeb988f"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        // vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch", true);
        vSeeds.emplace_back("testnet-seeds.bitcoin2m.org", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = (CCheckpointData) {
            {
               // {546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 00000000000001c200b9790dc637d3bb141fe77d155b966ed775b17e109f7c6c (height 1156179)
            1501802953,
            14706531,
            0.15
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.BCIHeight = 0;
        consensus.BCIPremineWindow = 0;
        consensus.BCIPremineEnforceWhitelist = false;
        consensus.BCICoinTransferAmount = 1851040046271426U;
        consensus.BCILastHeightWithReward = 281665;
        consensus.BCICoinTransferHeight = 850;
        consensus.BitcoinPostforkBlock = uint256();
        consensus.BitcoinPostforkTime = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitStart = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitLegacy = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        //based on https://github.com/BTCGPU/BTCGPU/issues/78
        consensus.nPowAveragingWindow = 30;
        consensus.nPowMaxAdjustDown = 16;
        consensus.nPowMaxAdjustUp = 32;
        consensus.nPowTargetTimespanLegacy = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStartLegacy[0] = 0xfa;
        pchMessageStartLegacy[1] = 0xbf;
        pchMessageStartLegacy[2] = 0xb5;
        pchMessageStartLegacy[3] = 0xda;
        
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;

        nDefaultPort = 18444;
        nBitcoinDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        const char* pszTimestamp = "regtest";
        genesis = CreateGenesisBlock(1535561891, pszTimestamp, uint256S("0x3e692e7c0820997c000000000000000000000000000000000000000000000000"), ParseHex("0d33bb78ec961a87eeb02eaed1057e0e1e54374393b0c7162c3f292bdce63571"), 0x1e00ffff, 1, 50 * COIN);
        //genesis = CreateGenesisBlock(1231006505, 2392468091, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash(consensus);
        
        assert(consensus.hashGenesisBlock == uint256S("0x0000000013f165e067d2a68f758d3aab1cc55ca8ee52af1ad26ebec76a4842cb"));
        assert(genesis.hashMerkleRoot == uint256S("0x2769af5d0f7b8847433d17a064e4c8f82a3e4d7e26e98748177c3725c1ca063f"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
    }
    
};

class BitcoinAddressChainParam : public CMainParams
{
public:
    BitcoinAddressChainParam()
    {
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
    }
};

static std::unique_ptr<CChainParams> globalChainParams;
static BitcoinAddressChainParam chainParamsForAddressConversion;

const CChainParams &Params()
{
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams &BitcoinAddressFormatParams()
{
    return chainParamsForAddressConversion;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}


