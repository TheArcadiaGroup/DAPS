// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletdb.h"

#include "base58.h"
#include "protocol.h"
#include "serialize.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet.h"

#include <boost/filesystem.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/thread.hpp>
#include <fstream>

using namespace boost;
using namespace std;

static uint64_t nAccountingEntryNumber = 0;

//
// CWalletDB
//

bool CWalletDB::AppendStealthAccountList(const std::string& accountName) {
    std::string currentList;
    if (!ReadStealthAccountList(currentList)) {
        currentList = accountName;
    } else {
        currentList = currentList + "," + accountName;
        nWalletDBUpdated++;
        Erase(std::string("accountlist"));
    }
    nWalletDBUpdated++;
    return Write(std::string("accountlist"), currentList);
}

bool CWalletDB::ReadStealthAccountList(std::string& accountList) {
    return Read(std::string("accountlist"), accountList);
}

bool CWalletDB::WriteName(const string& strAddress, const string& strName)
{
    nWalletDBUpdated++;
    return Write(make_pair(string("name"), strAddress), strName);
}

bool CWalletDB::EraseName(const string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    nWalletDBUpdated++;
    return Erase(make_pair(string("name"), strAddress));
}

bool CWalletDB::WritePurpose(const string& strAddress, const string& strPurpose)
{
    nWalletDBUpdated++;
    return Write(make_pair(string("purpose"), strAddress), strPurpose);
}

bool CWalletDB::ErasePurpose(const string& strPurpose)
{
    nWalletDBUpdated++;
    return Erase(make_pair(string("purpose"), strPurpose));
}

bool CWalletDB::WriteTx(uint256 hash, const CWalletTx& wtx)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("tx"), hash), wtx);
}

bool CWalletDB::EraseTx(uint256 hash)
{
    nWalletDBUpdated++;
    return Erase(std::make_pair(std::string("tx"), hash));
}

bool CWalletDB::WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta)
{
    nWalletDBUpdated++;

    if (!Write(std::make_pair(std::string("keymeta"), vchPubKey),
            keyMeta, false))
        return false;

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return Write(std::make_pair(std::string("key"), vchPubKey), std::make_pair(vchPrivKey, Hash(vchKey.begin(), vchKey.end())), false);
}

bool CWalletDB::WriteCryptedKey(const CPubKey& vchPubKey,
    const std::vector<unsigned char>& vchCryptedSecret,
    const CKeyMetadata& keyMeta)
{
    const bool fEraseUnencryptedKey = true;
    nWalletDBUpdated++;

    if (!Write(std::make_pair(std::string("keymeta"), vchPubKey),
            keyMeta))
        return false;

    if (!Write(std::make_pair(std::string("ckey"), vchPubKey), vchCryptedSecret, false))
        return false;
    if (fEraseUnencryptedKey) {
        Erase(std::make_pair(std::string("key"), vchPubKey));
        Erase(std::make_pair(std::string("wkey"), vchPubKey));
    }
    return true;
}

bool CWalletDB::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
}

bool CWalletDB::WriteCScript(const uint160& hash, const CScript& redeemScript)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("cscript"), hash), redeemScript, false);
}

bool CWalletDB::WriteWatchOnly(const CScript& dest)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("watchs"), dest), '1');
}

bool CWalletDB::EraseWatchOnly(const CScript& dest)
{
    nWalletDBUpdated++;
    return Erase(std::make_pair(std::string("watchs"), dest));
}

bool CWalletDB::WriteMultiSig(const CScript& dest)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("multisig"), dest), '1');
}

bool CWalletDB::WriteComboKeys(const ComboKeyList& combo)
{
	return Write(std::string("dapsmultisig"), combo);
}
bool CWalletDB::ReadAllComboKeys(ComboKeyList& comboData)
{
	return Read(std::string("dapsmultisig"), comboData);
}

bool CWalletDB::EraseMultiSig(const CScript& dest)
{
    nWalletDBUpdated++;
    return Erase(std::make_pair(std::string("multisig"), dest));
}

bool CWalletDB::WriteReserveAmount(const double& amount)
{
    nWalletDBUpdated++;
    return Write(std::string("reservebalance"), amount);
}

bool CWalletDB::ReadReserveAmount(double& amount)
{
    return Read(std::string("reservebalance"), amount);
}

bool CWalletDB::WriteBestBlock(const CBlockLocator& locator)
{
    nWalletDBUpdated++;
    return Write(std::string("bestblock"), locator);
}

bool CWalletDB::ReadBestBlock(CBlockLocator& locator)
{
    return Read(std::string("bestblock"), locator);
}

bool CWalletDB::WriteOrderPosNext(int64_t nOrderPosNext)
{
    nWalletDBUpdated++;
    return Write(std::string("orderposnext"), nOrderPosNext);
}

// presstab HyperStake
bool CWalletDB::WriteStakeSplitThreshold(uint64_t nStakeSplitThreshold)
{
    nWalletDBUpdated++;
    return Write(std::string("stakeSplitThreshold"), nStakeSplitThreshold);
}

//presstab HyperStake
bool CWalletDB::WriteMultiSend(std::vector<std::pair<std::string, int> > vMultiSend)
{
    nWalletDBUpdated++;
    bool ret = true;
    for (unsigned int i = 0; i < vMultiSend.size(); i++) {
        std::pair<std::string, int> pMultiSend;
        pMultiSend = vMultiSend[i];
        if (!Write(std::make_pair(std::string("multisend"), i), pMultiSend, true))
            ret = false;
    }
    return ret;
}
//presstab HyperStake
bool CWalletDB::EraseMultiSend(std::vector<std::pair<std::string, int> > vMultiSend)
{
    nWalletDBUpdated++;
    bool ret = true;
    for (unsigned int i = 0; i < vMultiSend.size(); i++) {
        std::pair<std::string, int> pMultiSend;
        pMultiSend = vMultiSend[i];
        if (!Erase(std::make_pair(std::string("multisend"), i)))
            ret = false;
    }
    return ret;
}
//presstab HyperStake
bool CWalletDB::WriteMSettings(bool fMultiSendStake, bool fMultiSendMasternode, int nLastMultiSendHeight)
{
    nWalletDBUpdated++;
    std::pair<bool, bool> enabledMS(fMultiSendStake, fMultiSendMasternode);
    std::pair<std::pair<bool, bool>, int> pSettings(enabledMS, nLastMultiSendHeight);

    return Write(std::string("msettingsv2"), pSettings, true);
}
//presstab HyperStake
bool CWalletDB::WriteMSDisabledAddresses(std::vector<std::string> vDisabledAddresses)
{
    nWalletDBUpdated++;
    bool ret = true;
    for (unsigned int i = 0; i < vDisabledAddresses.size(); i++) {
        if (!Write(std::make_pair(std::string("mdisabled"), i), vDisabledAddresses[i]))
            ret = false;
    }
    return ret;
}
//presstab HyperStake
bool CWalletDB::EraseMSDisabledAddresses(std::vector<std::string> vDisabledAddresses)
{
    nWalletDBUpdated++;
    bool ret = true;
    for (unsigned int i = 0; i < vDisabledAddresses.size(); i++) {
        if (!Erase(std::make_pair(std::string("mdisabled"), i)))
            ret = false;
    }
    return ret;
}
bool CWalletDB::WriteAutoCombineSettings(bool fEnable, CAmount nCombineThreshold)
{
    nWalletDBUpdated++;
    std::pair<bool, CAmount> pSettings;
    pSettings.first = fEnable;
    pSettings.second = nCombineThreshold;
    return Write(std::string("autocombinesettings"), pSettings, true);
}

bool CWalletDB::WriteDefaultKey(const CPubKey& vchPubKey)
{
    nWalletDBUpdated++;
    return Write(std::string("defaultkey"), vchPubKey);
}

bool CWalletDB::ReadPool(int64_t nPool, CKeyPool& keypool)
{
    return Read(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CWalletDB::WritePool(int64_t nPool, const CKeyPool& keypool)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CWalletDB::ErasePool(int64_t nPool)
{
    nWalletDBUpdated++;
    return Erase(std::make_pair(std::string("pool"), nPool));
}

bool CWalletDB::WriteMinVersion(int nVersion)
{
    return Write(std::string("minversion"), nVersion);
}

bool CWalletDB::WriteStakingStatus(bool status) {
    return Write(std::string("stakingstatus"), status);
}

bool CWalletDB::WriteNumSigners(int numSigners) {
    return Write(std::string("numsigners"), numSigners);
}

int CWalletDB::ReadNumSigners() {
    int ret = 0;
    if (!Read(std::string("numsigners"), ret)) {
        return 0;
    }
    return ret;
}

void CWalletDB::WriteScreenIndex(int index)
{
	Write(std::string("screenindex"), index);
}

int CWalletDB::ReadScreenIndex()
{
	int ret = 0;
	if (!Read(std::string("screenindex"), ret)) {
		return 0;
	}
	return ret;
}

bool CWalletDB::ReadStakingStatus() {
    bool status;
    if (!Read(std::string("stakingstatus"), status)) {
        return false;
    }
    return status;
}

bool CWalletDB::WriteScannedBlockHeight(int height)
{
	return Write(std::string("scannedblockheight"), height);
}
bool CWalletDB::ReadScannedBlockHeight(int& height)
{
	return Read(std::string("scannedblockheight"), height);
}

bool CWalletDB::Write2FA(bool status)
{
    return Write(std::string("2fa"), status);
}
bool CWalletDB::Read2FA()
{
    bool status;
    if (!Read(std::string("2fa"), status)) {
        return false;
    }
    return status;
}

bool CWalletDB::Write2FASecret(std::string secret)
{
    return Write(std::string("2fasecret"), secret);
}
std::string CWalletDB::Read2FASecret()
{
    std::string secret;
    if (!Read(std::string("2fasecret"), secret))
        return "";
    return secret;
}

bool CWalletDB::Write2FAPeriod(int period)
{
    return Write(std::string("2faperiod"), period);
}
int CWalletDB::Read2FAPeriod()
{
    int period;
    if (!Read(std::string("2faperiod"), period))
        return 0;
    return period;
}


bool CWalletDB::Write2FALastTime(uint64_t lastTime)
{
    return Write(std::string("2falasttime"), lastTime);
}
uint64_t CWalletDB::Read2FALastTime()
{
    uint64_t lastTime;
    if (!Read(std::string("2falasttime"), lastTime))
        return 0;
    return lastTime;
}

bool CWalletDB::ReadAccount(const string& strAccount, CAccount& account)
{
    account.SetNull();
    return Read(make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::WriteAutoConsolidateSettingTime(uint32_t settingTime)
{
    return Write(std::string("autoconsolidatetime"), settingTime);
}

uint32_t CWalletDB::ReadAutoConsolidateSettingTime()
{
    uint32_t settingTime = 0;
    if (!Read(std::string("autoconsolidatetime"), settingTime)) {
        return 0;
    }
    return settingTime;
}


bool CWalletDB::WriteAccount(const string& strAccount, const CAccount& account)
{
    return Write(make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::ReadStealthAccount(const std::string& strAccount, CStealthAccount& account)
{
    if (strAccount == "masteraccount") {
        return ReadAccount("spendaccount", account.spendAccount) && ReadAccount("viewaccount", account.viewAccount);
    }
    return ReadAccount(strAccount + "spend", account.spendAccount) && ReadAccount(strAccount + "view", account.viewAccount);
}

bool CWalletDB::WriteStealthAccount(const std::string& strAccount, const CStealthAccount& account) {
    if (strAccount == "masteraccount") {
        return WriteAccount("spendaccount", account.spendAccount) && WriteAccount("viewaccount", account.viewAccount);
    }
    return WriteAccount(strAccount + "spend", account.spendAccount) && WriteAccount(strAccount + "view", account.viewAccount);
}

bool CWalletDB::WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry)
{
    return Write(std::make_pair(std::string("acentry"), std::make_pair(acentry.strAccount, nAccEntryNum)), acentry);
}

bool CWalletDB::WriteAccountingEntry_Backend(const CAccountingEntry& acentry)
{
    return WriteAccountingEntry(++nAccountingEntryNumber, acentry);
}

CAmount CWalletDB::GetAccountCreditDebit(const string& strAccount)
{
    list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    CAmount nCreditDebit = 0;
    for (const CAccountingEntry& entry : entries)
        nCreditDebit += entry.nCreditDebit;

    return nCreditDebit;
}

void CWalletDB::ListAccountCreditDebit(const string& strAccount, list<CAccountingEntry>& entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error("CWalletDB::ListAccountCreditDebit() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    while (true) {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << std::make_pair(std::string("acentry"), std::make_pair((fAllAccounts ? string("") : strAccount), uint64_t(0)));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0) {
            pcursor->close();
            throw runtime_error("CWalletDB::ListAccountCreditDebit() : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "acentry")
            break;
        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        ssKey >> acentry.nEntryNo;
        entries.push_back(acentry);
    }

    pcursor->close();
}

DBErrors CWalletDB::ReorderTransactions(CWallet* pwallet)
{
    LOCK(pwallet->cs_wallet);
    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef multimap<int64_t, TxPair> TxItems;
    TxItems txByTime;

    for (map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it) {
        CWalletTx* wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->nTimeReceived, TxPair(wtx, (CAccountingEntry*)0)));
    }
    list<CAccountingEntry> acentries;
    ListAccountCreditDebit("", acentries);
    for (CAccountingEntry& entry : acentries) {
        txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
    }

    int64_t& nOrderPosNext = pwallet->nOrderPosNext;
    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it) {
        CWalletTx* const pwtx = (*it).second.first;
        CAccountingEntry* const pacentry = (*it).second.second;
        int64_t& nOrderPos = (pwtx != 0) ? pwtx->nOrderPos : pacentry->nOrderPos;

        if (nOrderPos == -1) {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (pwtx) {
                if (!WriteTx(pwtx->GetHash(), *pwtx))
                    return DB_LOAD_FAIL;
            } else if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                return DB_LOAD_FAIL;
        } else {
            int64_t nOrderPosOff = 0;
            for (const int64_t& nOffsetStart : nOrderPosOffsets) {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (pwtx) {
                if (!WriteTx(pwtx->GetHash(), *pwtx))
                    return DB_LOAD_FAIL;
            } else if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                return DB_LOAD_FAIL;
        }
    }
    WriteOrderPosNext(nOrderPosNext);

    return DB_LOAD_OK;
}

class CWalletScanState
{
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    unsigned int nKeyMeta;
    bool fIsEncrypted;
    bool fAnyUnordered;
    int nFileVersion;
    vector<uint256> vWalletUpgrade;

    CWalletScanState()
    {
        nKeys = nCKeys = nKeyMeta = 0;
        fIsEncrypted = false;
        fAnyUnordered = false;
        nFileVersion = 0;
    }
};

bool ReadKeyValue(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue, CWalletScanState& wss, string& strType, string& strErr)
{
    try {
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;
        if (strType == "name") {
            string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CBitcoinAddress(strAddress).Get()].name;
        } else if (strType == "purpose") {
            string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[CBitcoinAddress(strAddress).Get()].purpose;
        } else if (strType == "tx") {
            uint256 hash;
            ssKey >> hash;
            CWalletTx wtx;
            ssValue >> wtx;
            CValidationState state;
            if (!(CheckTransaction(wtx, false, false, state) && (wtx.GetHash() == hash) && state.IsValid()))
                return false;

            if (wtx.nOrderPos == -1)
                wss.fAnyUnordered = true;

            pwallet->AddToWallet(wtx, true);
        } else if (strType == "acentry") {
            string strAccount;
            ssKey >> strAccount;
            uint64_t nNumber;
            ssKey >> nNumber;
            if (nNumber > nAccountingEntryNumber)
                nAccountingEntryNumber = nNumber;

            if (!wss.fAnyUnordered) {
                CAccountingEntry acentry;
                ssValue >> acentry;
                if (acentry.nOrderPos == -1)
                    wss.fAnyUnordered = true;
            }
        } else if (strType == "watchs") {
            CScript script;
            ssKey >> script;
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
                pwallet->LoadWatchOnly(script);

            // Watch-only addresses have no birthday information for now,
            // so set the wallet birthday to the beginning of time.
            pwallet->nTimeFirstKey = 1;
        } else if (strType == "multisig") {
            CScript script;
            ssKey >> script;
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
                pwallet->LoadMultiSig(script);

            // MultiSig addresses have no birthday information for now,
            // so set the wallet birthday to the beginning of time.
            pwallet->nTimeFirstKey = 1;
        } else if (strType == "key" || strType == "wkey") {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid()) {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash = 0;

            if (strType == "key") {
                wss.nKeys++;
                ssValue >> pkey;
            } else {
                CWalletKey wkey;
                ssValue >> wkey;
                pkey = wkey.vchPrivKey;
            }

            // Old wallets store keys as "key" [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private key
            // using EC operations as a checksum.
            // Newer wallets store keys as "key"[pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
            // remaining backwards-compatible.
            try {
                ssValue >> hash;
            } catch (...) {
            }

            bool fSkipCheck = false;

            if (hash != 0) {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey.begin(), vchKey.end()) != hash) {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck)) {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (!pwallet->LoadKey(key, vchPubKey)) {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        } else if (strType == "mkey") {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if (pwallet->mapMasterKeys.count(nID) != 0) {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        } else if (strType == "ckey") {
            vector<unsigned char> vchPubKey;
            ssKey >> vchPubKey;
            vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            wss.nCKeys++;

            if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey)) {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        } else if (strType == "keymeta") {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            pwallet->LoadKeyMetadata(vchPubKey, keyMeta);

            // find earliest key creation time, as wallet birthday
            if (!pwallet->nTimeFirstKey ||
                (keyMeta.nCreateTime < pwallet->nTimeFirstKey))
                pwallet->nTimeFirstKey = keyMeta.nCreateTime;
        } else if (strType == "defaultkey") {
            ssValue >> pwallet->vchDefaultKey;
        } else if (strType == "pool") {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;
            pwallet->setKeyPool.insert(nIndex);

            // If no metadata exists yet, create a default with the pool key's
            // creation time. Note that this may be overwritten by actually
            // stored metadata for that key later, which is fine.
            CKeyID keyid = keypool.vchPubKey.GetID();
            if (pwallet->mapKeyMetadata.count(keyid) == 0)
                pwallet->mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
        } else if (strType == "version") {
            ssValue >> wss.nFileVersion;
            if (wss.nFileVersion == 10300)
                wss.nFileVersion = 300;
        } else if (strType == "cscript") {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> script;
            if (!pwallet->LoadCScript(script)) {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        } else if (strType == "orderposnext") {
            ssValue >> pwallet->nOrderPosNext;
        } else if (strType == "stakeSplitThreshold") //presstab HyperStake
        {
            ssValue >> pwallet->nStakeSplitThreshold;
        } else if (strType == "multisend") //presstab HyperStake
        {
            unsigned int i;
            ssKey >> i;
            std::pair<std::string, int> pMultiSend;
            ssValue >> pMultiSend;
            if (CBitcoinAddress(pMultiSend.first).IsValid()) {
                pwallet->vMultiSend.push_back(pMultiSend);
            }
        } else if (strType == "msettingsv2") //presstab HyperStake
        {
            std::pair<std::pair<bool, bool>, int> pSettings;
            ssValue >> pSettings;
            pwallet->fMultiSendStake = pSettings.first.first;
            pwallet->fMultiSendMasternodeReward = pSettings.first.second;
            pwallet->nLastMultiSendHeight = pSettings.second;
        } else if (strType == "mdisabled") //presstab HyperStake
        {
            std::string strDisabledAddress;
            ssValue >> strDisabledAddress;
            pwallet->vDisabledAddresses.push_back(strDisabledAddress);
        } else if (strType == "autocombinesettings") {
            std::pair<bool, CAmount> pSettings;
            ssValue >> pSettings;
            pwallet->fCombineDust = true;//pSettings.first;
            pwallet->nAutoCombineThreshold = 540*COIN;//pSettings.second;
        } else if (strType == "destdata") {
            std::string strAddress, strKey, strValue;
            ssKey >> strAddress;
            ssKey >> strKey;
            ssValue >> strValue;
            if (!pwallet->LoadDestData(CBitcoinAddress(strAddress).Get(), strKey, strValue)) {
                strErr = "Error reading wallet database: LoadDestData failed";
                return false;
            }
        } else if (strType == "hdchain") {
            CHDChain chain;
            ssValue >> chain;
            if (!pwallet->SetHDChain(chain, true))
            {
                strErr = "Error reading wallet database: SetHDChain failed";
                return false;
            }
        }
        else if (strType == "chdchain")
        {
            CHDChain chain;
            ssValue >> chain;
            if (!pwallet->SetCryptedHDChain(chain, true))
            {
                strErr = "Error reading wallet database: SetHDCryptedChain failed";
                return false;
            }
        }
        else if (strType == "hdpubkey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;

            CHDPubKey hdPubKey;
            ssValue >> hdPubKey;

            if(vchPubKey != hdPubKey.extPubKey.pubkey)
            {
                strErr = "Error reading wallet database: CHDPubKey corrupt";
                return false;
            }
            if (!pwallet->LoadHDPubKey(hdPubKey))
            {
                strErr = "Error reading wallet database: LoadHDPubKey failed";
                return false;
            }
        }
    } catch (...) {
        return false;
    }
    return true;
}

static bool IsKeyType(string strType)
{
    return (strType == "key" || strType == "wkey" ||
            strType == "mkey" || strType == "ckey");
}

DBErrors CWalletDB::LoadWallet(CWallet* pwallet)
{
    pwallet->vchDefaultKey = CPubKey();
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((string) "minversion", nMinVersion)) {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor) {
            LogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true) {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0) {
                LogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            string strType, strErr;
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr)) {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType))
                    result = DB_CORRUPT;
                else {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    if (strType == "tx")
                        // Rescan if there is a bad transaction record:
                        SoftSetBoolArg("-rescan", true);
                }
            }
            if (!strErr.empty())
                LogPrintf("%s\n", strErr);
        }
        pcursor->close();
    } catch (boost::thread_interrupted) {
        throw;
    } catch (...) {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DB_LOAD_OK)
        return result;

    LogPrintf("nFileVersion = %d\n", wss.nFileVersion);

    LogPrintf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n",
        wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys) != wss.nKeyMeta)
        pwallet->nTimeFirstKey = 1; // 0 would be considered 'no value'

    for (uint256 hash : wss.vWalletUpgrade)
        WriteTx(hash, pwallet->mapWallet[hash]);

    // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
    if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000))
        return DB_NEED_REWRITE;

    if (wss.nFileVersion < CLIENT_VERSION) // Update
        WriteVersion(CLIENT_VERSION);

    if (wss.fAnyUnordered)
        result = ReorderTransactions(pwallet);

    pwallet->laccentries.clear();
    ListAccountCreditDebit("*", pwallet->laccentries);
    for(CAccountingEntry& entry : pwallet->laccentries) {
        pwallet->wtxOrdered.insert(make_pair(entry.nOrderPos, CWallet::TxPair((CWalletTx*)0, &entry)));
    }

    return result;
}

DBErrors CWalletDB::FindWalletTx(CWallet* pwallet, vector<uint256>& vTxHash, vector<CWalletTx>& vWtx)
{
    pwallet->vchDefaultKey = CPubKey();
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
        LOCK(pwallet->cs_wallet);
        int nMinVersion = 0;
        if (Read((string) "minversion", nMinVersion)) {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor) {
            LogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true) {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0) {
                LogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            string strType;
            ssKey >> strType;
            if (strType == "tx") {
                uint256 hash;
                ssKey >> hash;

                CWalletTx wtx;
                ssValue >> wtx;

                vTxHash.push_back(hash);
                vWtx.push_back(wtx);
            }
        }
        pcursor->close();
    } catch (boost::thread_interrupted) {
        throw;
    } catch (...) {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    return result;
}

DBErrors CWalletDB::ZapWalletTx(CWallet* pwallet, vector<CWalletTx>& vWtx)
{
    // build list of wallet TXs
    vector<uint256> vTxHash;
    DBErrors err = FindWalletTx(pwallet, vTxHash, vWtx);
    if (err != DB_LOAD_OK)
        return err;

    // erase each wallet TX
    for (uint256& hash : vTxHash) {
        if (!EraseTx(hash))
            return DB_CORRUPT;
    }

    return DB_LOAD_OK;
}

void ThreadFlushWalletDB(const string& strFile)
{
    // Make this thread recognisable as the wallet flushing thread
    RenameThread("dapscoin-wallet");

    static bool fOneThread;
    if (fOneThread)
        return;
    fOneThread = true;
    if (!GetBoolArg("-flushwallet", true))
        return;

    unsigned int nLastSeen = nWalletDBUpdated;
    unsigned int nLastFlushed = nWalletDBUpdated;
    int64_t nLastWalletUpdate = GetTime();
    while (true) {
        MilliSleep(500);

        if (nLastSeen != nWalletDBUpdated) {
            nLastSeen = nWalletDBUpdated;
            nLastWalletUpdate = GetTime();
        }

        if (nLastFlushed != nWalletDBUpdated && GetTime() - nLastWalletUpdate >= 2) {
            TRY_LOCK(bitdb.cs_db, lockDb);
            if (lockDb) {
                // Don't do this if any databases are in use
                int nRefCount = 0;
                map<string, int>::iterator mi = bitdb.mapFileUseCount.begin();
                while (mi != bitdb.mapFileUseCount.end()) {
                    nRefCount += (*mi).second;
                    mi++;
                }

                if (nRefCount == 0) {
                    boost::this_thread::interruption_point();
                    map<string, int>::iterator mi = bitdb.mapFileUseCount.find(strFile);
                    if (mi != bitdb.mapFileUseCount.end()) {
                        LogPrint("db", "Flushing multisig_wallet.dat\n");
                        nLastFlushed = nWalletDBUpdated;
                        int64_t nStart = GetTimeMillis();

                        // Flush multisig_wallet.dat so it's self contained
                        bitdb.CloseDb(strFile);
                        bitdb.CheckpointLSN(strFile);

                        bitdb.mapFileUseCount.erase(mi++);
                        LogPrint("db", "Flushed multisig_wallet.dat %dms\n", GetTimeMillis() - nStart);
                    }
                }
            }
        }
    }
}

bool BackupWallet(const CWallet& wallet, const string& strDest)
{
    if (!wallet.fFileBacked)
        return false;
    while (true) {
        {
            LOCK(bitdb.cs_db);
            if (!bitdb.mapFileUseCount.count(wallet.strWalletFile) || bitdb.mapFileUseCount[wallet.strWalletFile] == 0) {
                // Flush log data to the dat file
                bitdb.CloseDb(wallet.strWalletFile);
                bitdb.CheckpointLSN(wallet.strWalletFile);
                bitdb.mapFileUseCount.erase(wallet.strWalletFile);

                // Copy multisig_wallet.dat
                filesystem::path pathSrc = GetDataDir() / wallet.strWalletFile;
                filesystem::path pathDest(strDest);
                if (filesystem::is_directory(pathDest))
                    pathDest /= wallet.strWalletFile;

                try {
#if BOOST_VERSION >= 158000
                    filesystem::copy_file(pathSrc, pathDest, filesystem::copy_option::overwrite_if_exists);
#else
                    std::ifstream src(pathSrc.string(), std::ios::binary);
                    std::ofstream dst(pathDest.string(), std::ios::binary);
                    dst << src.rdbuf();
#endif
                    LogPrintf("copied multisig_wallet.dat to %s\n", pathDest.string());
                    return true;
                } catch (const filesystem::filesystem_error& e) {
                    LogPrintf("error copying multisig_wallet.dat to %s - %s\n", pathDest.string(), e.what());
                    return false;
                }
            }
        }
        MilliSleep(100);
    }
    return false;
}

//
// Try to (very carefully!) recover multisig_wallet.dat if there is a problem.
//
bool CWalletDB::Recover(CDBEnv& dbenv, std::string filename, bool fOnlyKeys)
{
    // Recovery procedure:
    // move multisig_wallet.dat to multisig_wallet.timestamp.bak
    // Call Salvage with fAggressive=true to
    // get as much data as possible.
    // Rewrite salvaged data to multisig_wallet.dat
    // Set -rescan so any missing transactions will be
    // found.
    int64_t now = GetTime();
    std::string newFilename = strprintf("wallet.%d.bak", now);

    int result = dbenv.dbenv.dbrename(NULL, filename.c_str(), NULL,
        newFilename.c_str(), DB_AUTO_COMMIT);
    if (result == 0)
        LogPrintf("Renamed %s to %s\n", filename, newFilename);
    else {
        LogPrintf("Failed to rename %s to %s\n", filename, newFilename);
        return false;
    }

    std::vector<CDBEnv::KeyValPair> salvagedData;
    bool allOK = dbenv.Salvage(newFilename, true, salvagedData);
    if (salvagedData.empty()) {
        LogPrintf("Salvage(aggressive) found no records in %s.\n", newFilename);
        return false;
    }
    LogPrintf("Salvage(aggressive) found %u records\n", salvagedData.size());

    bool fSuccess = allOK;
    boost::scoped_ptr<Db> pdbCopy(new Db(&dbenv.dbenv, 0));
    int ret = pdbCopy->open(NULL, // Txn pointer
        filename.c_str(),         // Filename
        "main",                   // Logical db name
        DB_BTREE,                 // Database type
        DB_CREATE,                // Flags
        0);
    if (ret > 0) {
        LogPrintf("Cannot create database file %s\n", filename);
        return false;
    }
    CWallet dummyWallet;
    CWalletScanState wss;

    DbTxn* ptxn = dbenv.TxnBegin();
    for (CDBEnv::KeyValPair& row : salvagedData) {
        if (fOnlyKeys) {
            CDataStream ssKey(row.first, SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(row.second, SER_DISK, CLIENT_VERSION);
            string strType, strErr;
            bool fReadOK = ReadKeyValue(&dummyWallet, ssKey, ssValue,
                wss, strType, strErr);
            if (!IsKeyType(strType))
                continue;
            if (!fReadOK) {
                LogPrintf("WARNING: CWalletDB::Recover skipping %s: %s\n", strType, strErr);
                continue;
            }
        }
        Dbt datKey(&row.first[0], row.first.size());
        Dbt datValue(&row.second[0], row.second.size());
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE);
        if (ret2 > 0)
            fSuccess = false;
    }
    ptxn->commit(0);
    pdbCopy->close(0);

    return fSuccess;
}

bool CWalletDB::Recover(CDBEnv& dbenv, std::string filename)
{
    return CWalletDB::Recover(dbenv, filename, false);
}

bool CWalletDB::WriteDestData(const std::string& address, const std::string& key, const std::string& value)
{
    nWalletDBUpdated++;
    return Write(std::make_pair(std::string("destdata"), std::make_pair(address, key)), value);
}

bool CWalletDB::WriteTxPrivateKey(const std::string& outpointKey, const std::string& k)
{
	return Write(std::make_pair(std::string("txpriv"), outpointKey), k);
}

bool CWalletDB::ReadTxPrivateKey(const std::string& outpointKey, std::string& k)
{
	return Read(std::make_pair(std::string("txpriv"), outpointKey), k);
}

bool CWalletDB::WriteKeyImage(const std::string& outpointKey, const CKeyImage& k)
{
	return Write(std::make_pair(std::string("outpointkeyimage"), outpointKey), k);
}
bool CWalletDB::ReadKeyImage(const std::string& outpointKey, CKeyImage& k)
{
	return Read(std::make_pair(std::string("outpointkeyimage"), outpointKey), k);
}

bool CWalletDB::WriteHasWaitingTx(const bool hasWaitingTx)
{
    return Write(std::string("hasmultisigpendingtx"), hasWaitingTx);
}
bool CWalletDB::ReadHasWaitingTx()
{
    bool hasWaitingTx = false;
    Read(std::string("hasmultisigpendingtx"), hasWaitingTx);
    return hasWaitingTx;
}
bool CWalletDB::WritePendingForSigningTx(const CPartialTransaction& ptx)
{
    return Write(std::string("pendingforsigningtx"), ptx);
}
bool CWalletDB::ReadPendingForSigningTx(CPartialTransaction& ptx) 
{
    return Read(std::string("pendingforsigningtx"), ptx);
}

bool CWalletDB::EraseDestData(const std::string& address, const std::string& key)
{
    nWalletDBUpdated++;
    return Erase(std::make_pair(std::string("destdata"), std::make_pair(address, key)));
}

bool CWalletDB::WriteHDChain(const CHDChain& chain)
{
    nWalletDBUpdated++;
    return Write(std::string("hdchain"), chain);
}

bool CWalletDB::WriteCryptedHDChain(const CHDChain& chain)
{
    nWalletDBUpdated++;

    if (!Write(std::string("chdchain"), chain))
        return false;

    Erase(std::string("hdchain"));

    return true;
}


bool CWalletDB::WriteHDPubKey(const CHDPubKey& hdPubKey, const CKeyMetadata& keyMeta)
{
    nWalletDBUpdated++;

    if (!Write(std::make_pair(std::string("keymeta"), hdPubKey.extPubKey.pubkey), keyMeta, false))
        return false;

    return Write(std::make_pair(std::string("hdpubkey"), hdPubKey.extPubKey.pubkey), hdPubKey, false);
}

// Just get the Serial Numbers
std::list<CBigNum> CWalletDB::ListMintedCoinsSerial()
{
    std::list<CBigNum> listPubCoin;
    
    return listPubCoin;
}

// Just get the Serial Numbers
std::list<CBigNum> CWalletDB::ListSpentCoinsSerial()
{
    std::list<CBigNum> listPubCoin;
    
    return listPubCoin;
}


