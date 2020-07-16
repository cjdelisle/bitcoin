// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
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
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

#define COIN COIN_BTC

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
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.CSVHeight = 419328; // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.SegwitHeight = 481824; // 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
        consensus.MinBIP9WarningHeight = consensus.SegwitHeight + consensus.nMinerConfirmationWindow;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000008ea3cf107ae0dec57f03fe8");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000000000000005f8920febd3925f8272a6a71237563d78c2edfdd09ddf"); // 597379

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
        nDefaultPort = 8333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 280;
        m_assumed_chain_state_size = 4;

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed.bitcoin.sipa.be"); // Pieter Wuille, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("dnsseed.bluematt.me"); // Matt Corallo, only supports x9
        vSeeds.emplace_back("dnsseed.bitcoin.dashjr.org"); // Luke Dashjr
        vSeeds.emplace_back("seed.bitcoinstats.com"); // Christian Decker, supports x1 - xf
        vSeeds.emplace_back("seed.bitcoin.jonasschnelli.ch"); // Jonas Schnelli, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("seed.btc.petertodd.org"); // Peter Todd, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("seed.bitcoin.sprovoost.nl"); // Sjors Provoost
        vSeeds.emplace_back("dnsseed.emzy.de"); // Stephan Oeste

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;

        checkpointData = {
            {
                { 11111, uint256S("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
                { 33333, uint256S("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
                { 74000, uint256S("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
                {105000, uint256S("0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
                {134444, uint256S("0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
                {168000, uint256S("0x000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
                {193000, uint256S("0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
                {210000, uint256S("0x000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
                {216116, uint256S("0x00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")},
                {225430, uint256S("0x00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")},
                {250000, uint256S("0x000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
                {279000, uint256S("0x0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")},
                {295000, uint256S("0x00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000000005f8920febd3925f8272a6a71237563d78c2edfdd09ddf
            /* nTime    */ 1569926786,
            /* nTxCount */ 460596047,
            /* dTxRate  */ 3.77848885073875,
        };
    }
};

#include <streams.h>

static CBlock PktGenerisBlock() {
    std::vector<unsigned char> bytes = ParseHex(
        "00000000000000000000000000000000000000000000"
		"0000000000000000000000000000df345ba23b13467eec222a919d449dab"
		"6506abc555ef307794ecd3d36ac891fb00000000ffff0f1f0000000001fd"
		"04160000000000000000df345ba23b13467eec222a919d449dab6506abc5"
		"55ef307794ecd3d36ac891fb00096e88ffff0f1f03000000000000003476"
		"07000098038000000000ffff0f2000000000000000000000000000000000"
		"000000000000000000000000000000000000000000000000000000000000"
		"000000000000000000000000000000000000000000000000000000000000"
		"e79d06f72d778459a76a989dbdded6d45b5e4358943c9aab1eb4e42a9c67"
		"f9ac317b762fe60198c3861255552928a179a5e9a6b9b7b7f4b44e02fc35"
		"19f92964fbbfb576d1e9ff3c588c60fb2643602ae1f5695f89460608d325"
		"0e57a7755385aaa0de52409159387de4145d92533cd5f2a0d6d2a21b6533"
		"11a40bd2556493171cf1beedf894a090626577d8042e72f9cdab8ab212b2"
		"d6ee5ca7b22169a01bf903ab05b248fb8ed5de5a2bb0cd3901fc2e3270ff"
		"a524ed3adfc9d7fe109d0e2755f016386a09eda81bd9707bf681d75cef82"
		"9f3f8ee0903bfdb2c86ff44628df573143ec832f41ae17e575e31848d9cf"
		"430930d81f41b0d803251b81f8181e543cb25c7dca4f2454f8f8bb86987d"
		"b019ceffe7f0a2be807767f85dc903d3b843af448d14d5214b6ad5812b4d"
		"82b8cbea25c69c6b87d667f9c18c2993d500ed902d4c539a7d06ab0ca95a"
		"fd946fd3702554e4bf9f76a1f087dccf33356b7efa9149fa6b4949159d03"
		"cb6e7d13efe91134a9ed8adc7c7325d39201cb2c2c1e2191c5e9d3d71dc5"
		"d1232e4cfc603fc5aa994d7bb8d190ca3d7c0e2fb9abb68df80c2cdfd8d1"
		"19aec1a9c62c0ef7af9375e56c0330263332c4c879bcda52de73fea26781"
		"eb3dfa19dd2399b605050198fca80467bdca4a50980a3a37aa552f65caf9"
		"634b18fca475551d0a37dceab5f78c1cfdb48917122137cb74e236800c06"
		"84936b9cc0ca563025cb68609be37869fa8e95bb6fdcd15320b3d5b2fabe"
		"9524f464dbfabe36ef958170b5d7f25c40938bd287a5540b00e06ccb40f5"
		"58958b72541e8ca4f4f965e4f78898085b34fdb6e33b1f588b6d0abc4cb1"
		"19a8f54e0d949a08afb87979d4c69165ac6bd9e694369a3903ec24c1e3a5"
		"2c401c88e035a9f6aed6909f3a2b6dbe60e6fa842400c4164c21dc4c8b23"
		"25b70ad1829bed742717776ff28457b384f4bdd0bf48b2db2d18f89af671"
		"c58ecded320cf289b8fa9cfd53fcd7352de1cff3c41d2f7f8ec6f280d8a9"
		"d6933da42b66a6a3d30d46742e9cd793388a07e5e15b9b220b4209415537"
		"214447d386abce2c74a24b7dc60ff9ce04a7cad19ab679d0234ac95e535a"
		"bd57d3ac91747b2f2cfe1f01bb944502b827fc8d2c5e8f920fb145188027"
		"1991e5f5db796ea8d392138cd18f602dc6deb3149c44e5085fbd77dc9975"
		"71e4652009b555253eefd215fb009b14e0e880f67d45e85a8252e457ddd0"
		"ace7cfdd5eec6cee070125b50307b7ab0f3983f32f58b75fb02133f3e077"
		"8c089484d07058e76025855909ff64b7c2ace114b6c302a087acc140be90"
		"679fe1d0a75300573dc000000000ffff0f20000000000000000000000000"
		"000000000000000000000000000000000000000000000000000000000000"
		"000000000000000000000000000000000000000000000000000000000000"
		"000000007594c5be146f727d7fb815193044fb2596ceca3a9b62252e5259"
		"ed56b7fb63cd2fe906fac0f3ff25658998198d9431a48a0be55a0a84333f"
		"bdabab0c318930b97d3bb1fa8a8ddeb1587f97c531f81963c70784089465"
		"e2ef4f465b8d6bb9bbb27f36971c87b98ccae3f8d445181b03c97a84ac8a"
		"12241b47d9845f966cedade1c31faa857bf2cafae9c71041dd23124d4cd4"
		"d6dff24cf632e94dd68831639b0f3aba27219cd8a869936605760ae408ca"
		"deef02c410fc2eeb412bdd7e411614e7830f54ebe0ea6eadae5fe226a67c"
		"0b310d4d4b5d10b47dfe2f165191e69c96e617ef8c3cf763fa49662deb82"
		"a2270b49816f11d56a3493c5e74b0eafbd9492e5fbaa0e0d6600c179a75c"
		"2c134e1d6a1c3721616b6241273b904aec0ef516c402649d032d5e4de8a1"
		"fb15bbeb250f5b6993b6bf5a39314e626d177578fedcc3f7935307321f8f"
		"25ae008855b1f19ddf26bcfa1636b3db132a737b4e1ec50ac9b223670f04"
		"a746be5c06e1de90115385c706af7eb947b9b712f9c14998d31b977ace19"
		"a1f2051799fe7aa47bc02f358f2d839891854825a7e7491e343eb5aa2d46"
		"8e787989abf9961e21956c5ced5c6a5375e809ad958235fc91989fa41412"
		"30c42ccbf6a50c6ca61e3780d65dbfc112a104cc1da5b1dd7ea024d2e37d"
		"b0bb10ab6f06242589cb5383927ac5d130b189d32e4731ec1e8b675caf6c"
		"4da531db3c598c5da69aa8ddcecae67cefd633fd80f994cec4ad28c2f142"
		"1b316999c1043c749b14a645f785dd56e8fdbc959ff03648336b0c9c9ca3"
		"c86bb96738750b855dffa0b74c9c492580dcbbb892b91d76359aedc0a3d8"
		"9a447b23f5449433bb7c4554eb6f0eb8ee63b9df12287f92eb23b3956d39"
		"33eeccf88ca9d9fe19a9a29a2821909f3a2b6dbe60e6fa842400c4164c21"
		"dc4c8b2325b70ad1829bed742717776ff28457b384f4bdd0bf48b2db2d18"
		"f89af671c58ecded320cf289b8fa9cfd53fcd7352de1cff3c41d2f7f8ec6"
		"f280d8a9d6933da42b66a6a3d30d46742e9cd793388a07e5e15b9b220b42"
		"09415537214447d386abce2c74a24b7dc60ff9ce04a7cad19ab679d0234a"
		"c95e535abd57d3ac91747b2f2cfe1f01bb944502b827fc8d2c5e8f920fb1"
		"451880271991e5f5db796ea8d392138cd18f602dc6deb3149c44e5085fbd"
		"77dc997571e4652009b555253eefd215fb009b14e0e880f67d45e85a8252"
		"e457ddd0ace7cfdd5eec6cee070125b50307b7ab0f3983f32f58b75fb021"
		"ace16c1a11a478a77f48ec8beda4f4912aa3337010343c14412cbc2f6d8c"
		"eb38dc88989cfee876ab00042a8000000000ffff0f200000000000000000"
		"000000000000000000000000000000000000000000000000000000000000"
		"000000000000000000000000000000000000000000000000000000000000"
		"00000000000000009653aa497eb0bf1f7b9170967201419b6ced537def43"
		"63a0b2869d974a91d4458b4099f8d9a5f8555219c9b6efd193e1c745636d"
		"42cd705557c48e47598648c42e1c94318744855d037b3de60b626de12f06"
		"be4ec366527100b35ea8d4626eac5c2461d733c072811aa87bb5a39edf46"
		"d13a318f948367fe7a130359cd2a1ed04a60ee497723623b258cecd2581a"
		"4d7cc3d7e9d05ae4d63ffcecdd16a19decb7dcffc9a9faccb2084177e736"
		"170f191b99446049304f95a2dad137670c0944a41dd36cd356ad70f65eab"
		"a46732e7976b4d252980db9e82ff554a599aae46dd27886e61a22adf51db"
		"f26be34bbc766510ddebb15a9bef63ba3052fe7f71252807582e08fa1301"
		"fd78138917fec593f50758f103966bcf45c32071a279367c90d2728d9d13"
		"a90c3ee64682b86b80738f4ad1cc94e8d2c98d70bc99e72b45a68f471946"
		"5bd291177ef8675eb9ab2cca7599bb8470180137e6d0e92dcd13fd60dfa8"
		"569175055e76d0df50c79447df8a0d6c64d1d240aae79168de62becc2409"
		"7a5da77de3d860efbf3fbb7a737275944899df27a45b9a7203d813dad5c6"
		"ebd0986535a260589a51843ae43bf17902282439ce50ae75ab4ad8f99453"
		"0750fc1b30d7dc364828b76275e3536950834c0afeb17ad04a0a3090cd4e"
		"1165b65727b08c939e355a5c992d87bd80c3a41465bf1b41d304646fbbfb"
		"6b350208282945b68d3a0440bb8d2dabf1b3767ccc02174499f4084be56f"
		"7733052ac65bec5401b9e627bb4094c8c5fad47a0afb5ab1a7db4de6e318"
		"f535013c8db58d16e5455fb0d2aa32a4d8e4d403412db7ecc718e459e81f"
		"09fde3523436ef6104f96201f1fa8c4251033198d39d0c5a87eae9b9499e"
		"b2b3551d4e579103de55354c95b4c3b0cee177cb443e85e4936100efb659"
		"bb7356a52f5d51682673e9cf655c9cec51d100979ffbf74922dfeaecf1bf"
		"1ac55933c73d5f3fe927674fd5afc5d5a85e5b8d9779d7352de1cff3c41d"
		"2f7f8ec6f280d8a9d6933da42b66a6a3d30d46742e9cd793388a07e5e15b"
		"9b220b4209415537214447d386abce2c74a24b7dc60ff9ce04a7cad19ab6"
		"79d0234ac95e535abd57d3ac91747b2f2cfe1f01bb944502b827fc8d2c5e"
		"8f920fb1451880271991e5f5db796ea8d392138cd18f602dc6deb3149c44"
		"e5085fbd77dc997571e4652009b555253eefd215fb009b14e0e880f67d45"
		"e85a8252e457ddd0ace7cfdd5eec6cee070125b50307b7ab0f3983f32f58"
		"b75fb0213ab54f4815c5fb0803d5ddd6d4278fc7105e5a15aff36d31ba05"
		"dd094c5d2b1f59974dd4d04c369300cb318000000000ffff0f2000000000"
		"000000000000000000000000000000000000000000000000000000000000"
		"000000000000000000000000000000000000000000000000000000000000"
		"000000000000000000000000d120d39a00a6aeb9703eaa6410db4990a504"
		"e21cdc0ccc4f913441b647104b4f0b8b87661db287ccaa443f2920759e0b"
		"9524babb4e227c7cc6a0ee765ff26b15ac81d3e764d6e4f8527edf236288"
		"ca56196d55a51a8c2a7cb9f9fd7f235a459fb9f77454c0a0cfbd71605850"
		"dcb3ad5428614ef576b3cc358a2286bd7089a0459aea9c86741eb0e4e295"
		"ec976b94efcb4441e998c8e51758de78301ed490f799867355ecd7c57c1d"
		"6adfcb2f789f53f47ddd22fb6dad62b4d1b7315001c5b341a265587a3826"
		"5e0e3ea811e53fbee01786efedc6bab28d0ece33016c96a7a52cc1c77cb8"
		"eb932020b883222dbb8a3c9209b7a8e9ef54828b205a63ce185fa813409d"
		"4589c203b782fae087f59141aca33b8a89af33314de4b215fb61821c03d7"
		"6f0ac07d2d97e5cad8fe5864de4269ddb23e0cbf4b53170a4b43da80e7d1"
		"28f07a471f4ed7e81a9d4ab038cd4cb570c810bd4386b882b29d965824d6"
		"51fdade58fa18a231a2ad288ed5fb0a1716c45c24b80a332d5d8cd56d6f6"
		"63b5b5bec1854bb2477b43bfa482d32577ebe6f775f1349c71fb98c49ecc"
		"d2a6a984b29da8664e0715ce25b520e58622a207fd6f58b95a37b095308e"
		"25672bca89d742faebbf8e397d5847a50266d4c8f76bdb9306d105a8a7d8"
		"3d20ab07a8769fc1c64ae92233115a91352458a11f329b2b227b07e7aac5"
		"439354fd30e4c1ef22ed6061bdd65020347eb495e40f7ed2d5e5dd6e6cbd"
		"34dcdb1078f771c3c93c8e2f989fd4af8e4704acdae9f0a71e154bf6d0ad"
		"a9efd1fc6a176299a3ef71fa650484d1d7062835a92def53df596633bf39"
		"bf0383f30674ea81003187222c48d8d91989bfd41d40edde7b07c29f8da3"
		"e0446cc6f5c58f2941af4418658bc55c20dec60859c8e8f8545263179afd"
		"f5c1b48aedc0fb4b71bf00cd0e53e86d3af5350ba6ed0b283e2fbbe3333a"
		"2856b81f4db572f5193ef5c7561dd6c22e3c0b411fd711529e69bf05811b"
		"2e8ed4fcec0080b506394154245190535ebdf909fbaae9ced09b8f63f925"
		"e9170701598f9757e4db71546f4a4bbe4ad32be2f551f3841e3125881a47"
		"50ad6684076e0cf8a9565c3dfe5140b7b40f3578867a19cf652bef184f9e"
		"d2ad63bfa62e16bd8bb52232d76b171559acaa7c51d56103a83735f0d5b1"
		"ae3bc720e5085fbd77dc997571e4652009b555253eefd215fb009b14e0e8"
		"80f67d45e85a8252e457ddd0ace7cfdd5eec6cee070125b50307b7ab0f39"
		"83f32f58b75fb0218228bfd8f3d022cd5a99786769f3a3e038e68fc7021f"
		"d54e8745ea09380d112f5846acb6b0b693a1ad015ae6d04e43116192dc9e"
		"dcdcdf52b2ece486afccac3a84da182bc48b69b3dec842c1d5f76abe2f91"
		"55a322a03808f708af8b589bdd206c338a2fefa693bc9dc232bdb3c03d1f"
		"a32b1da8a4514de4fccb2df8c0ffa2036dc15a92cd13bcb938f3d76853db"
		"406ece5f3bbfc6adb556855af805acdf2b1784fba6e61c1288024f8609b9"
		"cee016f3b09c07b1e3257c03fc6f6a2bf40fd597d326d3eb2bb10c6a4412"
		"cb8e260153008a482f7315f2235a3ae044df7004944fddec3a3eba0095fc"
		"b7432c07752f662e57559217925a030083452f8322f71a201497ceb1aa8e"
		"fea84504687932b1630f8440cd8b5b835424a99a6ba6ef531f0039c96dc9"
		"df6ddb1da17db6192d68265aa69fe8e7591d29f883799f4e8530085220cf"
		"e3d522c74c00ec447082de3f07f03e4cf6f427b0f2e54fa73d0ee631d7e6"
		"32101d487173ab63a5a014250a34f900730eb4554c4fcaff9e11e9051a3d"
		"7142d74708aadc2e29e3dec6fa67563527027c92a77e85f39702b90f8695"
		"48e8d203f4b9166fd7ea1032e793228ea8ed223fa6d69ffef6c9ceca87df"
		"21a33bf16d0095ccd7de5c20364a71f63933bc5e9f3269497e6bdc1969d6"
		"f4e2106a5ed1adcd971f9af95e595d00953c1527674ba6b82b0f8f6ce97d"
		"ed33774c8defd97c5ff1efc54617984d68bde405e946062e16004f841e6d"
		"1cb21d25f844c947d9db391b6394537f0ee65b2670abcb51acb86515aa98"
		"155916420e00dadfa924a79604be0074b78bdba7439f6ac8a0b028c43947"
		"f32cf1bde6af3dc9ffc3b36837c2e20083968aa01025b298c3f70f00028c"
		"0ed271ba1f8a425d46a81e480ad932dce9f46a84d6ccfe205403ad32dc1b"
		"571683788d29b2db5a793410d9a5843fb29d60ab294e0ccc2f35bfe1593e"
		"112a44dd3408760054899838af83022b08c6b224b92da9961cf8e5c518c0"
		"82f07b037c87f56d1c711e4564c8c3061b57767b6ffd2cb2f782d8a02db3"
		"4ba0d94f6a0f8664af79fff0eac78b47b753df86cdb06ebe88017a391df9"
		"656bf69eac1536d4237d19b601b632f65c35b264d0b634d17e2d8882af7c"
		"f5859b752801210e474f50eb15a8e67cb2be55332de8c389d1beeddfc275"
		"a3efeeb25ef6eadc57f4ab65436f7600d93cd72a0ee92af81941141ba58b"
		"6e361510f10bf66ff61ca2a3b6e0c83114d96bf382431fa21c00c9d818dc"
		"76721ed0ed09838560630ce2e2fc3ff2796727f0ded2147f68c040bf0b06"
		"c99184f0b53b13e966dd46b6224663f591dcb06be2c15398ad79af615547"
		"8d888c0cec4d0f008f0469a084a21a006ad610832938232cd672079fd672"
		"c29cfe44a9fe28029e4474b1d0efdf09ca6c99958969864e1a0483236c9a"
		"496f6753bd1dae2169f4a4a665d28907e5347aa30b181fa891a3d13c9761"
		"2292424a7d21f89806e9ae3161be2e1067f7e5821c352cf985af08d990b2"
		"d5595dcf6aee29ba8f6a906990bb2407447e64dc31fdbb925dba72842768"
		"3ef16e6fcde7b982390314a10cc5bd8c3a3fc9d4b1544a966301dbfda478"
		"712ea9de748ed1120bd864dab49694680dfdf647cb5d263d0a591c737fd3"
		"815475cbf0006bf0b638870865f9118936e144b4e7315763a5e526450325"
		"e1966ed32af3ec4f5c07231e161f4f006d0b61cd3a747951d29a6af505a2"
		"7264206786b8de5339ea1972c7e11027e77f90a5c9b11f5d2800490da63f"
		"1a94ffbb0bccc057f1be13eeae5cc8da783d3b84e2ae3aa424f54a663a4a"
		"9f9e67810f00b833ec0156377a6b96eb8b53e335f018af4b8be94118485b"
		"2d3b53652e890526d1a41bded7141400a8cc33116507392c3db3dddf3291"
		"d97543c77e9a2c616dfe130f23d0bc3733b0f2843d32c51d0e04e7932ad2"
		"1ec5e9be6dd6b86e541e2323ccf8b209ad0940b7222d4aaa91d8837fe42c"
		"f46b785af711ea8c6600320be68fcd657241e8efb16dde17e25f5adcf601"
		"aed934acfb3a82a2245a46f8b224527eb3ca48beab1f052a044b9a7ef7d1"
		"2a11c7e81bc72b0d3fce26f522a6180a762742d1e0ea79950a000f653cf3"
		"48876d1b2a42b4c7524dc906089023d96eff593c6eb9f0f4ecbd32480000"
		"010100000001000000000000000000000000000000000000000000000000"
		"0000000000000000ffffffff0100ffffffff020000008011040000220020"
		"d5c1005c0d4012d3ae2672319e7f9eb15a57516aeefabbbc062265f67e30"
		"8f2b0000000000000000326a3009f91102ffff0f20f935b3001ef51ba8f2"
		"4921a404bc376a0c713274bd1cc68c2c57f66f5c0be7ca00100000000000"
		"0000000000");
    CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    stream >> block;
    return block;
}


/**
 * PKT blockchain
 */
class CPKTParams : public CChainParams {
public:
    CPKTParams() {
        strNetworkID = "pkt";
        consensus.nSubsidyHalvingInterval = -1;
        consensus.BIP16Exception = uint256S("0x");
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x");
        consensus.BIP65Height = 0; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 0; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.CSVHeight = 0; // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.SegwitHeight = 0; // 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
        consensus.MinBIP9WarningHeight = consensus.SegwitHeight + consensus.nMinerConfirmationWindow;
        consensus.powLimit = uint256S("000fffff00000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = (14 * 24 * 60 * 60) / 10; // two weeks
        consensus.nPowTargetSpacing = (10 * 60) / 10;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        consensus.pow = Consensus::POW_PACKETCRYPT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0x00;
        pchMessageStart[2] = 0x2f;
        pchMessageStart[3] = 0x08;
        nDefaultPort = 64764;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 4;
        m_assumed_chain_state_size = 1;

        genesis = PktGenerisBlock();
        consensus.hashGenesisBlock = genesis.GetHash();
        printf("consensus.hashGenesisBlock = %s\n", genesis.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x0bdc1712a46194e552cf417ab0439c2d4f456c35cf63a0a406964c6f93432d85"));
        assert(genesis.hashMerkleRoot == uint256S("0xfb91c86ad3d3ec947730ef55c5ab0665ab9d449d912a22ec7e46133ba25b34df"));

        vSeeds.emplace_back("seed.cjd.li");
        vSeeds.emplace_back("seed.gridfinity.com");
        vSeeds.emplace_back("seed.anode.co");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0x75);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,0x38);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,0xe0);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x6b, 0x85, 0xc5, 0x3f};
        base58Prefixes[EXT_SECRET_KEY] = {0x6b, 0x86, 0x3b, 0xed};

        bech32_hrp = "pkt";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;

        checkpointData = {
            {
                { 11111, uint256S("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
                { 33333, uint256S("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
                { 74000, uint256S("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
                {105000, uint256S("0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
                {134444, uint256S("0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
                {168000, uint256S("0x000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
                {193000, uint256S("0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
                {210000, uint256S("0x000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
                {216116, uint256S("0x00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")},
                {225430, uint256S("0x00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")},
                {250000, uint256S("0x000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
                {279000, uint256S("0x0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")},
                {295000, uint256S("0x00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000000005f8920febd3925f8272a6a71237563d78c2edfdd09ddf
            /* nTime    */ 1569926786,
            /* nTxCount */ 460596047,
            /* dTxRate  */ 3.77848885073875,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105");
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.CSVHeight = 770112; // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.SegwitHeight = 834624; // 00000000002b980fcd729daaa248fd9316a5200e9b367f4ff2c42453e84201ca
        consensus.MinBIP9WarningHeight = consensus.SegwitHeight + consensus.nMinerConfirmationWindow;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000012b2a3a62424f21c918");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000000000b7ab6ce61eb6d571003fbe5fe892da4c9b740c49a07542462d"); // 1580000

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 30;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch");
        vSeeds.emplace_back("seed.tbtc.petertodd.org");
        vSeeds.emplace_back("seed.testnet.bitcoin.sprovoost.nl");
        vSeeds.emplace_back("testnet-seed.bluematt.me"); // Just a static list of stable node(s), only supports x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;


        checkpointData = {
            {
                {546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000b7ab6ce61eb6d571003fbe5fe892da4c9b740c49a07542462d
            /* nTime    */ 1569741320,
            /* nTxCount */ 52318009,
            /* dTxRate  */ 0.1517002392872353,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
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

        bech32_hrp = "bcrt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    else if (chain == "pkt")
        return std::unique_ptr<CChainParams>(new CPKTParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
