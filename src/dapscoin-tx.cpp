// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "clientversion.h"
#include "coins.h"
#include "core_io.h"
#include "keystore.h"
#include "primitives/block.h" // for MAX_BLOCK_SIZE
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sign.h"
#include "ui_interface.h" // for _(...)
#include <univalue.h>
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

#include "secp256k1_bulletproofs.h"
#include "secp256k1_commitment.h"
#include "secp256k1_generator.h"
#include "secp256k1.h"
#include "secp256k1-mw/src/hash_impl.h"
#include "random.h"

#include <stdio.h>

#include <boost/algorithm/string.hpp>
#include <boost/assign/list_of.hpp>

#define MAX_FILE_LENGTH (1024 * 1024)       // 1MB

using namespace boost::assign;
using namespace std;

static bool fCreateBlank;
static map<string, UniValue> registers;
CClientUIInterface uiInterface;

static bool AppInitRawTx(int argc, char* argv[])
{
    //
    // Parameters
    //
    ParseParameters(argc, argv);

    // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
    if (!SelectParamsFromCommandLine()) {
        fprintf(stderr, "Error: Invalid combination of -regtest and -testnet.\n");
        return false;
    }

    fCreateBlank = GetBoolArg("-create", false);

    if (argc < 2 || mapArgs.count("-?") || mapArgs.count("-help")) {
        // First part of help message is specific to this utility
        std::string strUsage = _("Dapscoin Core dapscoin-tx utility version") + " " + FormatFullVersion() + "\n\n" +
                               _("Usage:") + "\n" +
                               "  dapscoin-tx [options] <hex-tx> [commands]  " + _("Update hex-encoded dapscoin transaction") + "\n" +
                               "  dapscoin-tx [options] -create [commands]   " + _("Create hex-encoded dapscoin transaction") + "\n" +
                               "\n";

        fprintf(stdout, "%s", strUsage.c_str());

        strUsage = HelpMessageGroup(_("Options:"));
        strUsage += HelpMessageOpt("-?", _("This help message"));
        strUsage += HelpMessageOpt("-create", _("Create new, empty TX."));
        strUsage += HelpMessageOpt("-json", _("Select JSON output"));
        strUsage += HelpMessageOpt("-txid", _("Output only the hex-encoded transaction id of the resultant transaction."));
        strUsage += HelpMessageOpt("-regtest", _("Enter regression test mode, which uses a special chain in which blocks can be solved instantly."));
        strUsage += HelpMessageOpt("-testnet", _("Use the test network"));
        strUsage += HelpMessageOpt("-signdaps", _("Sign a DAPS raw transaction"));

        fprintf(stdout, "%s", strUsage.c_str());


        strUsage = HelpMessageGroup(_("Commands:"));
        strUsage += HelpMessageOpt("delin=N", _("Delete input N from TX"));
        strUsage += HelpMessageOpt("viewkey=key", _("Private view key to sign DAPS transactions"));
        strUsage += HelpMessageOpt("spendkey=key", _("Private view key to sign DAPS transactions"));
        strUsage += HelpMessageOpt("delout=N", _("Delete output N from TX"));
        strUsage += HelpMessageOpt("in=TXID:VOUT", _("Add input to TX"));
        strUsage += HelpMessageOpt("locktime=N", _("Set TX lock time to N"));
        strUsage += HelpMessageOpt("nversion=N", _("Set TX version to N"));
        strUsage += HelpMessageOpt("outaddr=VALUE:ADDRESS", _("Add address-based output to TX"));
        strUsage += HelpMessageOpt("outscript=VALUE:SCRIPT", _("Add raw script output to TX"));
        strUsage += HelpMessageOpt("sign=SIGHASH-FLAGS", _("Add zero or more signatures to transaction") + ". " +
            _("This command requires JSON registers:") +
            _("prevtxs=JSON object") + ", " +
            _("privatekeys=JSON object") + ". " +
            _("See signrawtransaction docs for format of sighash flags, JSON objects."));
        fprintf(stdout, "%s", strUsage.c_str());

        strUsage = HelpMessageGroup(_("Register Commands:"));
        strUsage += HelpMessageOpt("load=NAME:FILENAME", _("Load JSON file FILENAME into register NAME"));
        strUsage += HelpMessageOpt("set=NAME:JSON-STRING", _("Set register NAME to given JSON-STRING"));
        fprintf(stdout, "%s", strUsage.c_str());

        return false;
    }
    return true;
}

static void RegisterSetJson(const string& key, const string& rawJson)
{
    UniValue val;
    if (!val.read(rawJson)) {
        string strErr = "Cannot parse JSON for key " + key;
        throw runtime_error(strErr);
    }

    registers[key] = val;
}

static void RegisterSet(const string& strInput)
{
    // separate NAME:VALUE in string
    size_t pos = strInput.find(':');
    if ((pos == string::npos) ||
        (pos == 0) ||
        (pos == (strInput.size() - 1)))
        throw runtime_error("Register input requires NAME:VALUE");

    string key = strInput.substr(0, pos);
    string valStr = strInput.substr(pos + 1, string::npos);

    RegisterSetJson(key, valStr);
}

static void RegisterLoad(const string& strInput)
{
    // separate NAME:FILENAME in string
    size_t pos = strInput.find(':');
    if ((pos == string::npos) ||
        (pos == 0) ||
        (pos == (strInput.size() - 1)))
        throw runtime_error("Register load requires NAME:FILENAME");

    string key = strInput.substr(0, pos);
    string filename = strInput.substr(pos + 1, string::npos);

    FILE* f = fopen(filename.c_str(), "r");
    if (!f) {
        string strErr = "Cannot open file " + filename;
        throw runtime_error(strErr);
    }

    // load file chunks into one big buffer
    string valStr;
    int totalLength = 0;
    while ((!feof(f)) && (!ferror(f)) && totalLength < MAX_FILE_LENGTH) {
        char buf[4096];
        int bread = fread(buf, 1, sizeof(buf), f);
        if (bread <= 0)
            break;

        totalLength += bread;
        valStr.insert(valStr.size(), buf, bread);
    }

    if (ferror(f)) {
        string strErr = "Error reading file " + filename;
        throw runtime_error(strErr);
    }

    if (totalLength > MAX_FILE_LENGTH) {
        string strErr = "Error reading big file " + filename;
        throw runtime_error(strErr);
    }

    fclose(f);

    // evaluate as JSON buffer register
    RegisterSetJson(key, valStr);
}

static void MutateTxVersion(CMutableTransaction& tx, const string& cmdVal)
{
    int64_t newVersion = atoi64(cmdVal);
    if (newVersion < 1 || newVersion > CTransaction::CURRENT_VERSION)
        throw runtime_error("Invalid TX version requested");

    tx.nVersion = (int)newVersion;
}

static void MutateTxLocktime(CMutableTransaction& tx, const string& cmdVal)
{
    int64_t newLocktime = atoi64(cmdVal);
    if (newLocktime < 0LL || newLocktime > 0xffffffffLL)
        throw runtime_error("Invalid TX locktime requested");

    tx.nLockTime = (unsigned int)newLocktime;
}

static void MutateTxAddInput(CMutableTransaction& tx, const string& strInput)
{
    // separate TXID:VOUT in string
    size_t pos = strInput.find(':');
    if ((pos == string::npos) ||
        (pos == 0) ||
        (pos == (strInput.size() - 1)))
        throw runtime_error("TX input missing separator");

    // extract and validate TXID
    string strTxid = strInput.substr(0, pos);
    if ((strTxid.size() != 64) || !IsHex(strTxid))
        throw runtime_error("invalid TX input txid");
    uint256 txid(strTxid);

    static const unsigned int minTxOutSz = 9;
    unsigned int nMaxSize = MAX_BLOCK_SIZE_LEGACY;
    static const unsigned int maxVout = nMaxSize / minTxOutSz;

    // extract and validate vout
    string strVout = strInput.substr(pos + 1, string::npos);
    int vout = atoi(strVout);
    if ((vout < 0) || (vout > (int)maxVout))
        throw runtime_error("invalid TX input vout");

    // append to transaction input list
    CTxIn txin(txid, vout);
    tx.vin.push_back(txin);
}

static void MutateTxAddOutAddr(CMutableTransaction& tx, const string& strInput)
{
    // separate VALUE:ADDRESS in string
    size_t pos = strInput.find(':');
    if ((pos == string::npos) ||
        (pos == 0) ||
        (pos == (strInput.size() - 1)))
        throw runtime_error("TX output missing separator");

    // extract and validate VALUE
    string strValue = strInput.substr(0, pos);
    CAmount value;
    if (!ParseMoney(strValue, value))
        throw runtime_error("invalid TX output value");

    // extract and validate ADDRESS
    string strAddr = strInput.substr(pos + 1, string::npos);
    CBitcoinAddress addr(strAddr);
    if (!addr.IsValid())
        throw runtime_error("invalid TX output address");

    // build standard output script via GetScriptForDestination()
    CScript scriptPubKey = GetScriptForDestination(addr.Get());

    // construct TxOut, append to transaction output list
    CTxOut txout(value, scriptPubKey);
    tx.vout.push_back(txout);
}

static void MutateTxAddOutScript(CMutableTransaction& tx, const string& strInput)
{
    // separate VALUE:SCRIPT in string
    size_t pos = strInput.find(':');
    if ((pos == string::npos) ||
        (pos == 0))
        throw runtime_error("TX output missing separator");

    // extract and validate VALUE
    string strValue = strInput.substr(0, pos);
    CAmount value;
    if (!ParseMoney(strValue, value))
        throw runtime_error("invalid TX output value");

    // extract and validate script
    string strScript = strInput.substr(pos + 1, string::npos);
    CScript scriptPubKey = ParseScript(strScript); // throws on err

    // construct TxOut, append to transaction output list
    CTxOut txout(value, scriptPubKey);
    tx.vout.push_back(txout);
}

static void MutateTxDelInput(CMutableTransaction& tx, const string& strInIdx)
{
    // parse requested deletion index
    int inIdx = atoi(strInIdx);
    if (inIdx < 0 || inIdx >= (int)tx.vin.size()) {
        string strErr = "Invalid TX input index '" + strInIdx + "'";
        throw runtime_error(strErr.c_str());
    }

    // delete input from transaction
    tx.vin.erase(tx.vin.begin() + inIdx);
}

static void MutateTxDelOutput(CMutableTransaction& tx, const string& strOutIdx)
{
    // parse requested deletion index
    int outIdx = atoi(strOutIdx);
    if (outIdx < 0 || outIdx >= (int)tx.vout.size()) {
        string strErr = "Invalid TX output index '" + strOutIdx + "'";
        throw runtime_error(strErr.c_str());
    }

    // delete output from transaction
    tx.vout.erase(tx.vout.begin() + outIdx);
}

static const unsigned int N_SIGHASH_OPTS = 6;
static const struct {
    const char* flagStr;
    int flags;
} sighashOptions[N_SIGHASH_OPTS] = {
    {"ALL", SIGHASH_ALL},
    {"NONE", SIGHASH_NONE},
    {"SINGLE", SIGHASH_SINGLE},
    {"ALL|ANYONECANPAY", SIGHASH_ALL | SIGHASH_ANYONECANPAY},
    {"NONE|ANYONECANPAY", SIGHASH_NONE | SIGHASH_ANYONECANPAY},
    {"SINGLE|ANYONECANPAY", SIGHASH_SINGLE | SIGHASH_ANYONECANPAY},
};

static bool findSighashFlags(int& flags, const string& flagStr)
{
    flags = 0;

    for (unsigned int i = 0; i < N_SIGHASH_OPTS; i++) {
        if (flagStr == sighashOptions[i].flagStr) {
            flags = sighashOptions[i].flags;
            return true;
        }
    }

    return false;
}

uint256 ParseHashUO(map<string, UniValue>& o, string strKey)
{
    if (!o.count(strKey))
        return 0;
    return ParseHashUV(o[strKey], strKey);
}

vector<unsigned char> ParseHexUO(map<string, UniValue>& o, string strKey)
{
    if (!o.count(strKey)) {
        vector<unsigned char> emptyVec;
        return emptyVec;
    }
    return ParseHexUV(o[strKey], strKey);
}

static void MutateTxSign(CMutableTransaction& tx, const string& flagStr)
{
    int nHashType = SIGHASH_ALL;

    if (flagStr.size() > 0)
        if (!findSighashFlags(nHashType, flagStr))
            throw runtime_error("unknown sighash flag/sign option");

    vector<CTransaction> txVariants;
    txVariants.push_back(tx);

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the raw tx:
    CMutableTransaction mergedTx(txVariants[0]);
    bool fComplete = true;
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);

    if (!registers.count("privatekeys"))
        throw runtime_error("privatekeys register variable must be set.");
    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    UniValue keysObj = registers["privatekeys"];
    fGivenKeys = true;

    for (unsigned int kidx = 0; kidx < keysObj.size(); kidx++) {
        if (!keysObj[kidx].isStr())
            throw runtime_error("privatekey not a string");
        CBitcoinSecret vchSecret;
        bool fGood = vchSecret.SetString(keysObj[kidx].getValStr());
        if (!fGood)
            throw runtime_error("privatekey not valid");

        CKey key = vchSecret.GetKey();
        tempKeystore.AddKey(key);
    }

    // Add previous txouts given in the RPC call:
    if (!registers.count("prevtxs"))
        throw runtime_error("prevtxs register variable must be set.");
    UniValue prevtxsObj = registers["prevtxs"];
    {
        for (unsigned int previdx = 0; previdx < prevtxsObj.size(); previdx++) {
            UniValue prevOut = prevtxsObj[previdx];
            if (!prevOut.isObject())
                throw runtime_error("expected prevtxs internal object");

            map<string, UniValue::VType> types = map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)("scriptPubKey", UniValue::VSTR);
            if (!prevOut.checkObject(types))
                throw runtime_error("prevtxs internal object typecheck fail");

            uint256 txid = ParseHashUV(prevOut["txid"], "txid");

            int nOut = atoi(prevOut["vout"].getValStr());
            if (nOut < 0)
                throw runtime_error("vout must be positive");

            vector<unsigned char> pkData(ParseHexUV(prevOut["scriptPubKey"], "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                CCoinsModifier coins = view.ModifyCoins(txid);
                if (coins->IsAvailable(nOut) && coins->vout[nOut].scriptPubKey != scriptPubKey) {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + coins->vout[nOut].scriptPubKey.ToString() + "\nvs:\n" +
                          scriptPubKey.ToString();
                    throw runtime_error(err);
                }
                if ((unsigned int)nOut >= coins->vout.size())
                    coins->vout.resize(nOut + 1);
                coins->vout[nOut].scriptPubKey = scriptPubKey;
                coins->vout[nOut].nValue = 0; // we don't know the actual output value
            }

            // if redeemScript given and private keys given,
            // add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash() &&
                prevOut.exists("redeemScript")) {
                UniValue v = prevOut["redeemScript"];
                vector<unsigned char> rsData(ParseHexUV(v, "redeemScript"));
                CScript redeemScript(rsData.begin(), rsData.end());
                tempKeystore.AddCScript(redeemScript);
            }
        }
    }

    const CKeyStore& keystore = tempKeystore;

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
        if (!coins || !coins->IsAvailable(txin.prevout.n)) {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = coins->vout[txin.prevout.n].scriptPubKey;

        txin.scriptSig.clear();
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);

        // ... and merge in other signatures:
        for (const CTransaction& txv : txVariants) {
            txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
        }
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&mergedTx, i)))
            fComplete = false;
    }

    if (fComplete) {
        // do nothing... for now
        // perhaps store this for later optional JSON output
    }

    tx = mergedTx;
}

static void MutateTx(CMutableTransaction& tx, const string& command, const string& commandVal)
{
    if (command == "nversion")
        MutateTxVersion(tx, commandVal);
    else if (command == "locktime")
        MutateTxLocktime(tx, commandVal);

    else if (command == "delin")
        MutateTxDelInput(tx, commandVal);
    else if (command == "in")
        MutateTxAddInput(tx, commandVal);

    else if (command == "delout")
        MutateTxDelOutput(tx, commandVal);
    else if (command == "outaddr")
        MutateTxAddOutAddr(tx, commandVal);
    else if (command == "outscript")
        MutateTxAddOutScript(tx, commandVal);

    else if (command == "sign")
        MutateTxSign(tx, commandVal);

    else if (command == "load")
        RegisterLoad(commandVal);

    else if (command == "set")
        RegisterSet(commandVal);

    else
        throw runtime_error("unknown command");
}

static void OutputTxJSON(const CTransaction& tx)
{
    UniValue entry(UniValue::VOBJ);
    TxToUniv(tx, 0, entry);

    string jsonOutput = entry.write(4);
    fprintf(stdout, "%s\n", jsonOutput.c_str());
}

static void OutputTxHash(const CTransaction& tx)
{
    string strHexHash = tx.GetHash().GetHex(); // the hex-encoded transaction hash (aka the transaction id)

    fprintf(stdout, "%s\n", strHexHash.c_str());
}

static void OutputTxHex(CTransaction tx)
{
    UniValue entry(UniValue::VOBJ);
    string strHex = EncodeHexTx(tx);
    string strHexHash = tx.GetHash().GetHex();
    entry.push_back(Pair("hex", strHex));
    entry.push_back(Pair("txid", strHexHash));

    fprintf(stdout, "%s\n", entry.write(4).c_str());
}

static void OutputTx(const CTransaction& tx)
{
    if (GetBoolArg("-json", false))
        OutputTxJSON(tx);
    else if (GetBoolArg("-txid", false))
        OutputTxHash(tx);
    else
        OutputTxHex(tx);
}

static string readStdin()
{
    char buf[4096];
    string ret;

    int totalLength = 0;
    while (!feof(stdin) && totalLength < MAX_FILE_LENGTH) {
        size_t bread = fread(buf, 1, sizeof(buf), stdin);
        ret.append(buf, bread);
        if (bread < sizeof(buf))
            break;

        totalLength += bread;
    }

    if (ferror(stdin))
        throw runtime_error("error reading stdin");
    if (totalLength > MAX_FILE_LENGTH)
        throw runtime_error("error reading stdin max length");

    boost::algorithm::trim_right(ret);

    return ret;
}


//----------------------------------------RINGCT AND BULLETPROOFS----------------------------
secp256k1_context2* GetContext()
{
    static secp256k1_context2* both;
    if (!both) both = secp256k1_context_create2(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return both;
}

secp256k1_scratch_space2* GetScratch()
{
    static secp256k1_scratch_space2* scratch;
    if (!scratch) scratch = secp256k1_scratch_space_create(GetContext(), 1024 * 1024 * 512);
    return scratch;
}

secp256k1_bulletproof_generators* GetGenerator()
{
    static secp256k1_bulletproof_generators* generator;
    if (!generator) generator = secp256k1_bulletproof_generators_create(GetContext(), &secp256k1_generator_const_g, 64 * 1024);
    return generator;
}

CKey computePrivateKey(const CTxOut& out, const CKey& view, const CKey& spend)
{
    unsigned char aR[65];
    //copy R into a
    CPubKey txPub = out.txPub;
    memcpy(aR, txPub.begin(), out.txPub.size());
    if (!secp256k1_ec_pubkey_tweak_mul(aR, out.txPub.size(), view.begin())) {
        throw runtime_error("Failed to compute private key");
    }
    uint256 HS = Hash(aR, aR + txPub.size());

    unsigned char HStemp[32];
    unsigned char spendTemp[32];
    memcpy(HStemp, HS.begin(), 32);
    memcpy(spendTemp, spend.begin(), 32);
    if (!secp256k1_ec_privkey_tweak_add(HStemp, spendTemp))
        throw runtime_error("Failed to do secp256k1_ec_privkey_tweak_add");
    CKey privKey;
    privKey.Set(HStemp, HStemp + 32, true);
    return privKey;
}

bool CreateCommitment(const unsigned char* blind, CAmount val, std::vector<unsigned char>& commitment)
{
    secp256k1_context2* both = GetContext();
    secp256k1_pedersen_commitment commitmentD;
    if (!secp256k1_pedersen_commit(both, &commitmentD, blind, val, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
        return false;
    }
    unsigned char output[33];
    if (!secp256k1_pedersen_commitment_serialize(both, output, &commitmentD)) {
        return false;
    }
    std::copy(output, output + 33, std::back_inserter(commitment));
    return true;
}

bool CreateCommitment(const CAmount val, CKey& blind, std::vector<unsigned char>& commitment)
{
    blind.MakeNewKey(true);
    return CreateCommitment(blind.begin(), val, commitment);
}

bool CreateCommitmentWithZeroBlind(const CAmount val, unsigned char* pBlind, std::vector<unsigned char>& commitment)
{
    memset(pBlind, 0, 32);
    return CreateCommitment(pBlind, val, commitment);
}

void add1s(std::string& s, int wantedSize)
{
    int currentLength = s.length();
    for (int i = 0; i < wantedSize - currentLength; i++) {
        s = "1" + s;
    }
}

bool encodeStealthBase58(const std::vector<unsigned char>& raw, std::string& stealth) 
{
    if (raw.size() != 71 && raw.size() != 79) {
        return false;
    }
    stealth = "";

    //Encoding Base58 using block=8 bytes
    int i = 0;
    while (i < (int)raw.size()) {
        std::vector<unsigned char> input8;
        std::copy(raw.begin() + i, raw.begin() + i + 8, std::back_inserter(input8)); //copy 8 bytes
        std::string out = EncodeBase58(input8);
        if (out.length() < 11) {
            add1s(out, 11);
        }
        stealth += out;
        i += 8;
        if (i + 8 > (int)raw.size()) {
            //the last block of 7
            std::vector<unsigned char> input7;
            std::copy(raw.begin() + i, raw.begin() + i + 7, std::back_inserter(input7)); //copy 7 bytes
            std::string out11 = EncodeBase58(input7);
            add1s(out11, 11);
            stealth += out11;
            i += 7;
        }
    }
    return true;
}

bool EncodeStealthPublicAddress(const std::vector<unsigned char>& pubViewKey, const std::vector<unsigned char>& pubSpendKey, std::string& pubAddrb58) 
{
    std::vector<unsigned char> pubAddr;
    pubAddr.push_back(18);                                                                 //1 byte
    std::copy(pubSpendKey.begin(), pubSpendKey.begin() + 33, std::back_inserter(pubAddr)); //copy 33 bytes
    std::copy(pubViewKey.begin(), pubViewKey.begin() + 33, std::back_inserter(pubAddr));   //copy 33 bytes
    uint256 h = Hash(pubAddr.begin(), pubAddr.end());
    unsigned char* begin = h.begin();
    pubAddr.push_back(*(begin));
    pubAddr.push_back(*(begin + 1));
    pubAddr.push_back(*(begin + 2));
    pubAddr.push_back(*(begin + 3));

    return encodeStealthBase58(pubAddr, pubAddrb58);
}

bool EncodeStealthPublicAddress(const CPubKey& pubViewKey, const CPubKey& pubSpendKey, std::string& pubAddr) 
{
    if (pubViewKey.IsCompressed() && pubSpendKey.IsCompressed()) {
        return EncodeStealthPublicAddress(pubViewKey.Raw(), pubSpendKey.Raw(), pubAddr);
    }
    return false;
}

bool EncodeIntegratedAddress(const std::vector<unsigned char>& pubViewKey, const std::vector<unsigned char>& pubSpendKey, uint64_t paymentID, std::string& pubAddrb58)
{
    std::vector<unsigned char> pubAddr;
    pubAddr.push_back(19);                                                                            //1 byte 19 for integrated address
    std::copy(pubSpendKey.begin(), pubSpendKey.begin() + 33, std::back_inserter(pubAddr));            //copy 33 bytes
    std::copy(pubViewKey.begin(), pubViewKey.begin() + 33, std::back_inserter(pubAddr));              //copy 33 bytes
    std::copy((char*)&paymentID, (char*)&paymentID + sizeof(paymentID), std::back_inserter(pubAddr)); //8 bytes of payment id
    uint256 h = Hash(pubAddr.begin(), pubAddr.end());
    unsigned char* begin = h.begin();
    pubAddr.push_back(*(begin));
    pubAddr.push_back(*(begin + 1));
    pubAddr.push_back(*(begin + 2));
    pubAddr.push_back(*(begin + 3));

    return encodeStealthBase58(pubAddr, pubAddrb58);
}

bool EncodeIntegratedAddress(const CPubKey& pubViewKey, const CPubKey& pubSpendKey, uint64_t paymentID, std::string& pubAddr)
{
    if (pubViewKey.IsCompressed() && pubSpendKey.IsCompressed()) {
        return EncodeIntegratedAddress(pubViewKey.Raw(), pubSpendKey.Raw(), paymentID, pubAddr);
    }
    return false;
}

bool RevealTxOutAmount(const CKey view, const CTxOut& out, CAmount& amount, CKey& blind) 
{
    CPubKey sharedSec;
    ECDHInfo::ComputeSharedSec(view, out.txPub, sharedSec);
    uint256 val = out.maskValue.amount;
    uint256 mask = out.maskValue.mask;
    CKey decodedMask;
    ECDHInfo::Decode(mask.begin(), val.begin(), sharedSec, decodedMask, amount);
        
    std::vector<unsigned char> commitment;
    if (CreateCommitment(decodedMask.begin(), amount, commitment)) {
        if (commitment == out.commitment) {
            blind.Set(decodedMask.begin(), decodedMask.end(), true);
            return true;
        } else {
            amount = 0;
            return false;
        }            
    }
    amount = 0;
    return false;
}

uint256 GetTxSignatureHash(const CTransaction& tx)
{
    CTransactionSignature cts(tx);
    return cts.GetHash();
}

bool makeRingCT(CDirtyRawTransaction& wtxNew, const CKey& view, const CKey& spend)
{
    int myIndex = wtxNew.myIndex;
    int ringSize = wtxNew.ringSize;

    secp256k1_context2* both = GetContext();
    int i = 0;
    for (CTxOut& out : wtxNew.vout) {
        if (!out.IsEmpty()) {
            secp256k1_pedersen_commitment commitment;
            CKey blind;
            blind.Set(wtxNew.blinds[i].begin(), wtxNew.blinds[i].end(), true);
            if (!secp256k1_pedersen_commit(both, &commitment, blind.begin(), out.nValue, &secp256k1_generator_const_h, &secp256k1_generator_const_g))
                throw runtime_error("Cannot commit commitment");
            unsigned char output[33];
            if (!secp256k1_pedersen_commitment_serialize(both, output, &commitment))
                throw runtime_error("Cannot serialize commitment");
            out.commitment.clear();
            std::copy(output, output + 33, std::back_inserter(out.commitment));
        }
        i++;
    }

    const size_t MAX_VIN = MAX_TX_INPUTS;
    const size_t MAX_DECOYS = MAX_RING_SIZE; 
    const size_t MAX_VOUT = 5;

    if (wtxNew.vin.size() > MAX_TX_INPUTS || wtxNew.vin.size() == 0) {
        throw runtime_error("You have attempted to send a total value that is comprised of more than 50 smaller deposits. This is a rare occurrence, and lowering the total value sent, or sending the same total value in two separate transactions will usually work around this limitation.");
        return false;
    }

    for (size_t i = 0; i < wtxNew.vin.size(); i++) {
        if (wtxNew.vin[i].decoys.size() != wtxNew.vin[0].decoys.size()) {
            throw runtime_error("All inputs should have the same number of decoys");
            return false;
        }
    }

    if (wtxNew.vin[0].decoys.size() > MAX_DECOYS || wtxNew.vin[0].decoys.size() < MIN_RING_SIZE) {
        throw runtime_error("Too many decoys");
        return false; //maximum decoys = 15
    }

    std::vector<secp256k1_pedersen_commitment> myInputCommiments;
    int totalCommits = wtxNew.vin.size() + wtxNew.vout.size();
    int npositive = wtxNew.vin.size();
    unsigned char myBlinds[MAX_VIN + MAX_VIN + MAX_VOUT + 1][32]; //myBlinds is used for compuitng additional private key in the ring =
    memset(myBlinds, 0, (MAX_VIN + MAX_VIN + MAX_VOUT + 1) * 32);
    const unsigned char* bptr[MAX_VIN + MAX_VIN + MAX_VOUT + 1];
    //all in pubkeys + an additional public generated from commitments
    unsigned char allInPubKeys[MAX_VIN + 1][MAX_DECOYS + 1][33];
    unsigned char allKeyImages[MAX_VIN + 1][33];
    unsigned char allInCommitments[MAX_VIN][MAX_DECOYS + 1][33];
    unsigned char allOutCommitments[MAX_VOUT][33];

    int myBlindsIdx = 0;
    //additional member in the ring = Sum of All input public keys + sum of all input commitments - sum of all output commitments
    for (size_t j = 0; j < wtxNew.vin.size(); j++) {
        const CTxOut& inCTxOut = wtxNew.fullDecoys[j][myIndex + 1];
        CKey tmp = computePrivateKey(inCTxOut, view, spend);

        //compute key images
        unsigned char ki[33];
        PointHashingSuccessively(tmp.GetPubKey(), tmp.begin(), ki);
        wtxNew.vin[j].keyImage.Set(ki, ki + 33);

        memcpy(&myBlinds[myBlindsIdx][0], tmp.begin(), 32);
        bptr[myBlindsIdx] = &myBlinds[myBlindsIdx][0];
        myBlindsIdx++;
    }

    //Collecting input commitments blinding factors
    i = 0;
    for (CTxIn& in : wtxNew.vin) {
        const CTxOut& inCTxOut = wtxNew.fullDecoys[i][myIndex + 1];
        secp256k1_pedersen_commitment inCommitment;
        if (!secp256k1_pedersen_commitment_parse(both, &inCommitment, &(inCTxOut.commitment[0]))) {
            throw runtime_error("Cannot parse the commitment for inputs");
            return false;
        }

        myInputCommiments.push_back(inCommitment);
        CAmount tempAmount;
        CKey tmp;
        RevealTxOutAmount(view, inCTxOut, tempAmount, tmp);
        if (tmp.IsValid()) memcpy(&myBlinds[myBlindsIdx][0], tmp.begin(), 32);
        //verify input commitments
        std::vector<unsigned char> recomputedCommitment;
        if (!CreateCommitment(&myBlinds[myBlindsIdx][0], tempAmount, recomputedCommitment))
            throw runtime_error("Cannot create pedersen commitment");
        if (recomputedCommitment != inCTxOut.commitment) {
            throw runtime_error("Input commitments are not correct");
            return false;
        }

        bptr[myBlindsIdx] = myBlinds[myBlindsIdx];
        myBlindsIdx++;
        i++;
    }

    //collecting output commitment blinding factors
    i = 0;
    for (CTxOut& out : wtxNew.vout) {
        if (!out.IsEmpty()) {
            memcpy(&myBlinds[myBlindsIdx][0], wtxNew.blinds[i].data(), 32);
            bptr[myBlindsIdx] = &myBlinds[myBlindsIdx][0];
            myBlindsIdx++;
        }
        i++;
    }
    CKey newBlind;
    newBlind.MakeNewKey(true);
    memcpy(&myBlinds[myBlindsIdx][0], newBlind.begin(), 32);
    bptr[myBlindsIdx] = &myBlinds[myBlindsIdx][0];

    int myRealIndex = 0;
    if (myIndex != -1) {
        myRealIndex = myIndex + 1;
    }

    int PI = myRealIndex;
    unsigned char SIJ[MAX_VIN + 1][MAX_DECOYS + 1][32];
    unsigned char LIJ[MAX_VIN + 1][MAX_DECOYS + 1][33];
    unsigned char RIJ[MAX_VIN + 1][MAX_DECOYS + 1][33];
    unsigned char ALPHA[MAX_VIN + 1][32];
    unsigned char AllPrivKeys[MAX_VIN + 1][32];

    //generating LIJ and RIJ at PI: LIJ[j][PI], RIJ[j][PI], j=0..wtxNew.vin.size()
    for (size_t j = 0; j < wtxNew.vin.size(); j++) {
        const CTxOut& inCTxOut = wtxNew.fullDecoys[j][myIndex + 1];
        CKey tempPk = computePrivateKey(inCTxOut, view, spend);
        memcpy(AllPrivKeys[j], tempPk.begin(), 32);
        //copying corresponding key images
        memcpy(allKeyImages[j], wtxNew.vin[j].keyImage.begin(), 33);
        //copying corresponding in public keys
        CPubKey tempPubKey = tempPk.GetPubKey();
        memcpy(allInPubKeys[j][PI], tempPubKey.begin(), 33);

        memcpy(allInCommitments[j][PI], &(inCTxOut.commitment[0]), 33);
        CKey alpha;
        alpha.MakeNewKey(true);
        memcpy(ALPHA[j], alpha.begin(), 32);
        CPubKey LIJ_PI = alpha.GetPubKey();
        memcpy(LIJ[j][PI], LIJ_PI.begin(), 33);
        PointHashingSuccessively(tempPubKey, alpha.begin(), RIJ[j][PI]);
    }

    //computing additional input pubkey and key images
    //additional private key = sum of all existing private keys + sum of all blinds in - sum of all blind outs
    unsigned char outSum[32];
    if (!secp256k1_pedersen_blind_sum(both, outSum, (const unsigned char* const*)bptr, npositive + totalCommits, 2 * npositive))
        throw runtime_error("Cannot compute pedersen blind sum");
    memcpy(myBlinds[myBlindsIdx], outSum, 32);
    memcpy(AllPrivKeys[wtxNew.vin.size()], outSum, 32);
    CKey additionalPkKey;
    additionalPkKey.Set(myBlinds[myBlindsIdx], myBlinds[myBlindsIdx] + 32, true);
    CPubKey additionalPubKey = additionalPkKey.GetPubKey();
    memcpy(allInPubKeys[wtxNew.vin.size()][PI], additionalPubKey.begin(), 33);
    PointHashingSuccessively(additionalPubKey, myBlinds[myBlindsIdx], allKeyImages[wtxNew.vin.size()]);

    //verify that additional public key = sum of wtx.vin.size() real public keys + sum of wtx.vin.size() commitments - sum of wtx.vout.size() commitments - commitment to zero of transction fee

    //filling LIJ & RIJ at [j][PI]
    CKey alpha_additional;
    alpha_additional.MakeNewKey(true);
    memcpy(ALPHA[wtxNew.vin.size()], alpha_additional.begin(), 32);
    CPubKey LIJ_PI_additional = alpha_additional.GetPubKey();
    memcpy(LIJ[wtxNew.vin.size()][PI], LIJ_PI_additional.begin(), 33);
    PointHashingSuccessively(additionalPubKey, alpha_additional.begin(), RIJ[wtxNew.vin.size()][PI]);

    //Initialize SIJ except S[..][PI]
    for (int i = 0; i < (int)wtxNew.vin.size() + 1; i++) {
        for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
            if (j != PI) {
                CKey randGen;
                randGen.MakeNewKey(true);
                memcpy(SIJ[i][j], randGen.begin(), 32);
            }
        }
    }

    //extract all public keys
    for (int i = 0; i < (int)wtxNew.vin.size(); i++) {
        std::vector<COutPoint> decoysForIn;
        decoysForIn.push_back(wtxNew.vin[i].prevout);
        for (int j = 0; j < (int)wtxNew.vin[i].decoys.size(); j++) {
            decoysForIn.push_back(wtxNew.vin[i].decoys[j]);
        }
        for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
            if (j != PI) {
                const CTxOut& inCTxOut = wtxNew.fullDecoys[i][j];
                CPubKey extractedPub;
                if (!ExtractPubKey(inCTxOut.scriptPubKey, extractedPub)) {
                    throw runtime_error("Cannot extract public key from script pubkey");
                    return false;
                }
                memcpy(allInPubKeys[i][j], extractedPub.begin(), 33);
                memcpy(allInCommitments[i][j], &(inCTxOut.commitment[0]), 33);
            }
        }
    }

    secp256k1_pedersen_commitment allInCommitmentsPacked[MAX_VIN][MAX_DECOYS + 1];
    secp256k1_pedersen_commitment allOutCommitmentsPacked[MAX_VOUT + 1]; //+1 for tx fee

    for (size_t i = 0; i < wtxNew.vout.size(); i++) {
        memcpy(&(allOutCommitments[i][0]), &(wtxNew.vout[i].commitment[0]), 33);
        if (!secp256k1_pedersen_commitment_parse(both, &allOutCommitmentsPacked[i], allOutCommitments[i])) {
            throw runtime_error("Cannot parse the commitment for inputs");
            return false;
        }
    }

    //commitment to tx fee, blind = 0
    unsigned char txFeeBlind[32];
    memset(txFeeBlind, 0, 32);
    if (!secp256k1_pedersen_commit(both, &allOutCommitmentsPacked[wtxNew.vout.size()], txFeeBlind, wtxNew.nTxFee, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
        throw runtime_error("Cannot parse the commitment for transaction fee");
        return false;
    }

    //filling the additional pubkey elements for decoys: allInPubKeys[wtxNew.vin.size()][..]
    //allInPubKeys[wtxNew.vin.size()][j] = sum of allInPubKeys[..][j] + sum of allInCommitments[..][j] - sum of allOutCommitments
    const secp256k1_pedersen_commitment* outCptr[MAX_VOUT + 1];
    for (size_t i = 0; i < wtxNew.vout.size() + 1; i++) {
        outCptr[i] = &allOutCommitmentsPacked[i];
    }
    secp256k1_pedersen_commitment inPubKeysToCommitments[MAX_VIN][MAX_DECOYS + 1];
    for (int i = 0; i < (int)wtxNew.vin.size(); i++) {
        for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
            secp256k1_pedersen_serialized_pubkey_to_commitment(allInPubKeys[i][j], 33, &inPubKeysToCommitments[i][j]);
        }
    }
    for (int j = 0; j < (int)wtxNew.vin[0].decoys.size() + 1; j++) {
        if (j != PI) {
            const secp256k1_pedersen_commitment* inCptr[MAX_VIN * 2];
            for (int k = 0; k < (int)wtxNew.vin.size(); k++) {
                if (!secp256k1_pedersen_commitment_parse(both, &allInCommitmentsPacked[k][j], allInCommitments[k][j])) {
                    throw runtime_error("Cannot parse the commitment for inputs");
                }
                inCptr[k] = &allInCommitmentsPacked[k][j];
            }
            for (size_t k = wtxNew.vin.size(); k < 2 * wtxNew.vin.size(); k++) {
                inCptr[k] = &inPubKeysToCommitments[k - wtxNew.vin.size()][j];
            }
            secp256k1_pedersen_commitment out;
            size_t length;
            //convert allInPubKeys to pederson commitment to compute sum of all in public keys
            if (!secp256k1_pedersen_commitment_sum(both, inCptr, wtxNew.vin.size() * 2, outCptr, wtxNew.vout.size() + 1, &out))
                throw runtime_error("Cannot compute sum of commitment");
            if (!secp256k1_pedersen_commitment_to_serialized_pubkey(&out, allInPubKeys[wtxNew.vin.size()][j], &length))
                throw runtime_error("Cannot covert from commitment to public key");
        }
    }

    //Computing C
    int PI_interator = PI + 1; //PI_interator: PI + 1 .. wtxNew.vin[0].decoys.size() + 1 .. PI
    //unsigned char SIJ[wtxNew.vin.size() + 1][wtxNew.vin[0].decoys.size() + 1][32];
    //unsigned char LIJ[wtxNew.vin.size() + 1][wtxNew.vin[0].decoys.size() + 1][33];
    //unsigned char RIJ[wtxNew.vin.size() + 1][wtxNew.vin[0].decoys.size() + 1][33];
    unsigned char CI[MAX_DECOYS + 1][32];
    unsigned char tempForHash[2 * (MAX_VIN + 1) * 33 + 32];
    unsigned char* tempForHashPtr = tempForHash;
    for (size_t i = 0; i < wtxNew.vin.size() + 1; i++) {
        memcpy(tempForHashPtr, &LIJ[i][PI][0], 33);
        tempForHashPtr += 33;
        memcpy(tempForHashPtr, &RIJ[i][PI][0], 33);
        tempForHashPtr += 33;
    }
    uint256 ctsHash = GetTxSignatureHash(wtxNew);
    memcpy(tempForHashPtr, ctsHash.begin(), 32);

    if (PI_interator == (int)wtxNew.vin[0].decoys.size() + 1) PI_interator = 0;
    uint256 temppi1 = Hash(tempForHash, tempForHash + 2 * (wtxNew.vin.size() + 1) * 33 + 32);
    if (PI_interator == 0) {
        memcpy(CI[0], temppi1.begin(), 32);
    } else {
        memcpy(CI[PI_interator], temppi1.begin(), 32);
    }
    while (PI_interator != PI) {
        for (int j = 0; j < (int)wtxNew.vin.size() + 1; j++) {
            //compute LIJ
            unsigned char CP[33];
            memcpy(CP, allInPubKeys[j][PI_interator], 33);
            if (!secp256k1_ec_pubkey_tweak_mul(CP, 33, CI[PI_interator])) {
                throw runtime_error("Cannot compute LIJ for ring signature in secp256k1_ec_pubkey_tweak_mul");
            }
            if (!secp256k1_ec_pubkey_tweak_add(CP, 33, SIJ[j][PI_interator])) {
                throw runtime_error("Cannot compute LIJ for ring signature in secp256k1_ec_pubkey_tweak_add");
            }
            memcpy(LIJ[j][PI_interator], CP, 33);

            //compute RIJ
            //first compute CI * I
            memcpy(RIJ[j][PI_interator], allKeyImages[j], 33);
            if (!secp256k1_ec_pubkey_tweak_mul(RIJ[j][PI_interator], 33, CI[PI_interator])) {
                throw runtime_error("Cannot compute RIJ for ring signature in secp256k1_ec_pubkey_tweak_mul");
            }

            //compute S*H(P)
            unsigned char SHP[33];
            CPubKey tempP;
            tempP.Set(allInPubKeys[j][PI_interator], allInPubKeys[j][PI_interator] + 33);
            PointHashingSuccessively(tempP, SIJ[j][PI_interator], SHP);
            //convert shp into commitment
            secp256k1_pedersen_commitment SHP_commitment;
            secp256k1_pedersen_serialized_pubkey_to_commitment(SHP, 33, &SHP_commitment);

            //convert CI*I into commitment
            secp256k1_pedersen_commitment cii_commitment;
            secp256k1_pedersen_serialized_pubkey_to_commitment(RIJ[j][PI_interator], 33, &cii_commitment);

            const secp256k1_pedersen_commitment* twoElements[2];
            twoElements[0] = &SHP_commitment;
            twoElements[1] = &cii_commitment;

            secp256k1_pedersen_commitment sum;
            if (!secp256k1_pedersen_commitment_sum_pos(both, twoElements, 2, &sum))
                throw runtime_error("Cannot compute sum of commitments");
            size_t tempLength;
            if (!secp256k1_pedersen_commitment_to_serialized_pubkey(&sum, RIJ[j][PI_interator], &tempLength)) {
                throw runtime_error("Cannot compute two elements and serialize it to pubkey");
            }
        }

        PI_interator++;
        if (PI_interator == (int)wtxNew.vin[0].decoys.size() + 1) PI_interator = 0;

        int prev, ciIdx;
        if (PI_interator == 0) {
            prev = wtxNew.vin[0].decoys.size();
            ciIdx = 0;
        } else {
            prev = PI_interator - 1;
            ciIdx = PI_interator;
        }

        tempForHashPtr = tempForHash;
        for (int i = 0; i < (int)wtxNew.vin.size() + 1; i++) {
            memcpy(tempForHashPtr, LIJ[i][prev], 33);
            tempForHashPtr += 33;
            memcpy(tempForHashPtr, RIJ[i][prev], 33);
            tempForHashPtr += 33;
        }
        memcpy(tempForHashPtr, ctsHash.begin(), 32);
        uint256 ciHashTmp = Hash(tempForHash, tempForHash + 2 * (wtxNew.vin.size() + 1) * 33 + 32);
        memcpy(CI[ciIdx], ciHashTmp.begin(), 32);
    }

    //compute S[j][PI] = alpha_j - c_pi * x_j, x_j = private key corresponding to key image I
    for (size_t j = 0; j < wtxNew.vin.size() + 1; j++) {
        unsigned char cx[32];
        memcpy(cx, CI[PI], 32);
        if (!secp256k1_ec_privkey_tweak_mul(cx, AllPrivKeys[j]))
            throw runtime_error("Cannot compute EC mul");
        const unsigned char* sumArray[2];
        sumArray[0] = ALPHA[j];
        sumArray[1] = cx;
        if (!secp256k1_pedersen_blind_sum(both, SIJ[j][PI], sumArray, 2, 1))
            throw runtime_error("Cannot compute pedersen blind sum");
    }
    memcpy(wtxNew.c.begin(), CI[0], 32);
    //i for decoy index => PI
    for (int i = 0; i < (int)wtxNew.vin[0].decoys.size() + 1; i++) {
        std::vector<uint256> S_column;
        for (int j = 0; j < (int)wtxNew.vin.size() + 1; j++) {
            uint256 t;
            memcpy(t.begin(), SIJ[j][i], 32);
            S_column.push_back(t);
        }
        wtxNew.S.push_back(S_column);
    }
    wtxNew.ntxFeeKeyImage.Set(allKeyImages[wtxNew.vin.size()], allKeyImages[wtxNew.vin.size()] + 33);
    return true;
}

bool generateBulletProofAggregate(CDirtyRawTransaction& tx)
{
    unsigned char proof[2000];
    size_t len = 2000;
    const size_t MAX_VOUT = 5;
    unsigned char nonce[32];
    GetRandBytes(nonce, 32);
    unsigned char blinds[MAX_VOUT][32];
    uint64_t values[MAX_VOUT];
    size_t i = 0;
    const unsigned char* blind_ptr[MAX_VOUT];
    if (tx.vout.size() > MAX_VOUT) return false;
    memset(blinds, 0, tx.vout.size() * 32);
    for (i = 0; i < tx.vout.size(); i++) {
        memcpy(&blinds[i][0], tx.blinds[i].data(), 32);
        blind_ptr[i] = blinds[i];
        values[i] = tx.vout[i].nValue;
    }
    int ret = secp256k1_bulletproof_rangeproof_prove(GetContext(), GetScratch(), GetGenerator(), proof, &len, values, NULL, blind_ptr, tx.vout.size(), &secp256k1_generator_const_h, 64, nonce, NULL, 0);
    std::copy(proof, proof + len, std::back_inserter(tx.bulletproofs));
    return ret;
}

static void SignDirtyRawDAPSTx(CDirtyRawTransaction& tx, const CKey& view, const CKey& spend) {
    if (!makeRingCT(tx, view, spend)) {
        throw runtime_error("Failed to generate RingCT");
    }

    if (!generateBulletProofAggregate(tx)) {
        throw runtime_error("Failed to generate bulletproof");
    }

    for (size_t i = 0; i < tx.vout.size(); i++) {
        tx.vout[i].nValue = 0;
    }
}

static int CommandLineRawTx(int argc, char* argv[])
{
    string strPrint;
    int nRet = 0;
    try {
        // Skip switches; Permit common stdin convention "-"
        while (argc > 1 && IsSwitchChar(argv[1][0]) &&
               (argv[1][1] != 0)) {
            argc--;
            argv++;
        }

        CTransaction txDecodeTmp;
        CDirtyRawTransaction dirtyTxDecodeTmp;
        int startArg;
        bool signDAPSTx = true;
        if (!fCreateBlank) {
            // require at least one param
            if (argc < 2)
                throw runtime_error("too few parameters");

            // param: hex-encoded dapscoin transaction
            string strHexTx(argv[1]);
            if (strHexTx == "-") // "-" implies standard input
                strHexTx = readStdin();
            
            if (signDAPSTx) {
                if (!DecodeHexDirtyTx(dirtyTxDecodeTmp, strHexTx))
                    throw runtime_error("invalid transaction encoding");
            } else {
                if (!DecodeHexTx(txDecodeTmp, strHexTx))
                    throw runtime_error("invalid transaction encoding");
            }

            startArg = 2;
        } else
            startArg = 1;

        CMutableTransaction tx(txDecodeTmp);

        std::string viewKeyString, spendKeyString;
        for (int i = startArg; i < argc; i++) {
            string arg = argv[i];
            string key, value;
            size_t eqpos = arg.find('=');
            if (eqpos == string::npos)
                key = arg;
            else {
                key = arg.substr(0, eqpos);
                value = arg.substr(eqpos + 1);
            }
            if (!signDAPSTx) {
                MutateTx(tx, key, value);
            }
            if (key == "viewkey") {
                viewKeyString = value;
            }

            if (key == "spendkey") {
                spendKeyString = value;
            }
        }

        if (signDAPSTx) {
            CBitcoinSecret vchSecret, spendSecret;
            bool fGood = vchSecret.SetString(viewKeyString);
            if (!fGood) {
                throw runtime_error("view private key is invalid");
            }

            fGood = spendSecret.SetString(spendKeyString);
            if (!fGood) {
                throw runtime_error("spend private key is invalid");
            }

            CKey view = vchSecret.GetKey();
            CKey spend = spendSecret.GetKey();
            SignDirtyRawDAPSTx(dirtyTxDecodeTmp, view, spend);
            OutputTx(dirtyTxDecodeTmp);
        } else {
            OutputTx(tx);
        }
    }

    catch (boost::thread_interrupted) {
        throw;
    } catch (std::exception& e) {
        strPrint = string("error: ") + e.what();
        nRet = EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRawTx()");
        throw;
    }

    if (strPrint != "") {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}

int main(int argc, char* argv[])
{
    SetupEnvironment();

    try {
        if (!AppInitRawTx(argc, argv))
            return EXIT_FAILURE;
    } catch (std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRawTx()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInitRawTx()");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    try {
        ret = CommandLineRawTx(argc, argv);
    } catch (std::exception& e) {
        PrintExceptionContinue(&e, "CommandLineRawTx()");
    } catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRawTx()");
    }
    return ret;
}
