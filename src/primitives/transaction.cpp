// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"
#include "primitives/transaction.h"

#include "chain.h"
#include "hash.h"
#include "main.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "transaction.h"
#include "secp256k1.h"

#include <boost/foreach.hpp>

const int MIN_RING_SIZE = 11;
const int MAX_RING_SIZE = 15;
const int MAX_TX_INPUTS = 50;
const int MIN_TX_INPUTS_FOR_SWEEPING = 25;

//Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
void ecdhEncode(unsigned char* unmasked, unsigned char* amount, const unsigned char* sharedSec, int size)
{
    uint256 sharedSec1 = Hash(sharedSec, sharedSec + size);
    uint256 sharedSec2 = Hash(sharedSec1.begin(), sharedSec1.end());

    for (int i = 0; i < 32; i++) {
        unmasked[i] ^= *(sharedSec1.begin() + i);
    }
    unsigned char temp[32];
    memcpy(temp, amount, 32);
    for (int i = 0; i < 32; i++) {
        amount[i] = temp[i % 8] ^ *(sharedSec2.begin() + i);
    }
}
void ecdhDecode(unsigned char* masked, unsigned char* amount, const unsigned char* sharedSec, int size)
{
    uint256 sharedSec1 = Hash(sharedSec, sharedSec + size);
    uint256 sharedSec2 = Hash(sharedSec1.begin(), sharedSec1.end());

    for (int i = 0; i < 32; i++) {
        masked[i] ^= *(sharedSec1.begin() + i);
    }

    unsigned char temp[32];
    memcpy(temp, amount, 32);
    memset(amount, 0, 8);
    for (int i = 0; i < 32; i++) {
        amount[i] = temp[i % 8] ^ *(sharedSec2.begin() + i);
    }
}

void ECDHInfo::ComputeSharedSec(const CKey& priv, const CPubKey& pubKey, CPubKey& sharedSec)
{
    sharedSec.Set(pubKey.begin(), pubKey.end());
    unsigned char temp[65];
    memcpy(temp, sharedSec.begin(), sharedSec.size());
    if (!secp256k1_ec_pubkey_tweak_mul(temp, sharedSec.size(), priv.begin()))
        throw runtime_error("Cannot compute EC multiplication: secp256k1_ec_pubkey_tweak_mul");
    sharedSec.Set(temp, temp + 33);
}

void ECDHInfo::Encode(const CKey& mask, const CAmount& amount, const CPubKey& sharedSec, uint256& encodedMask, uint256& encodedAmount)
{
    memcpy(encodedMask.begin(), mask.begin(), 32);
    memcpy(encodedAmount.begin(), &amount, 32);
    ecdhEncode(encodedMask.begin(), encodedAmount.begin(), sharedSec.begin(), sharedSec.size());
}

void ECDHInfo::Decode(unsigned char* encodedMask, unsigned char* encodedAmount, const CPubKey& sharedSec, CKey& decodedMask, CAmount& decodedAmount)
{
    unsigned char tempAmount[32], tempDecoded[32];
    memcpy(tempDecoded, encodedMask, 32);
    decodedMask.Set(tempDecoded, tempDecoded + 32, 32);
    memcpy(tempAmount, encodedAmount, 32);
    memcpy(tempDecoded, decodedMask.begin(), 32);
    ecdhDecode(tempDecoded, tempAmount, sharedSec.begin(), sharedSec.size());
    memcpy(&decodedAmount, tempAmount, 8);

    decodedMask.Set(tempDecoded, tempDecoded + 32, true);
    memcpy(&decodedAmount, tempAmount, 8);
}

extern bool GetTransaction(const uint256 &hash, CTransaction &txOut, uint256 &hashBlock, bool fAllowSlow);

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString()/*.substr(0,10)*/, n);
}

std::string COutPoint::ToStringShort() const
{
    return strprintf("%s-%u", hash.ToString().substr(0,64), n);
}

uint256 COutPoint::GetHash()
{
    return Hash(BEGIN(hash), END(hash), BEGIN(n), END(n));
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24));
    if (nSequence != std::numeric_limits<unsigned int>::max())
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
    nRounds = -10;
}

bool COutPoint::IsMasternodeReward(const CTransaction* tx) const
{
    if(!tx->IsCoinStake())
        return false;

    return (n == tx->vout.size() - 1) && (tx->vout[1].scriptPubKey != tx->vout[n].scriptPubKey);
}

uint256 CTxOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, scriptPubKey.ToString().substr(0,30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), hasPaymentID(0), paymentID(0), txType(TX_TYPE_FULL), nTxFee(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), txPrivM(tx.txPrivM), hasPaymentID(tx.hasPaymentID), paymentID(tx.paymentID), txType(tx.txType), bulletproofs(tx.bulletproofs), nTxFee(tx.nTxFee), c(tx.c), S(tx.S), ntxFeeKeyImage(tx.ntxFeeKeyImage) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this);
}

std::string CMutableTransaction::ToString() const
{
    std::string str;
    str += strprintf("CMutableTransaction(ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

void CTransaction::UpdateHash() const
{
    *const_cast<uint256*>(&hash) = SerializeHash(*this);
}

CTransaction::CTransaction() : hash(), nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0), hasPaymentID(0), paymentID(0), txType(TX_TYPE_FULL), nTxFee(0) { }

CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), hasPaymentID(tx.hasPaymentID), paymentID(tx.paymentID), txType(tx.txType), bulletproofs(tx.bulletproofs), nTxFee(tx.nTxFee), c(tx.c), S(tx.S), ntxFeeKeyImage(tx.ntxFeeKeyImage) {
    UpdateHash();
}

CTransaction& CTransaction::operator=(const CTransaction &tx) {
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<CKey*>(&txPrivM) = tx.txPrivM;
    *const_cast<char*>(&hasPaymentID) = tx.hasPaymentID;
    *const_cast<uint64_t*>(&paymentID) = tx.paymentID;
    *const_cast<uint32_t*>(&txType) = tx.txType;
    bulletproofs = tx.bulletproofs;
    c = tx.c;
    S = tx.S;
    //*const_cast<std::vector<CKeyImage>*>(&keyImages) = tx.keyImages;
    //*const_cast<std::vector<std::vector<CTxIn>>*>(&decoys) = tx.decoys;
    nTxFee = tx.nTxFee;
    ntxFeeKeyImage = tx.ntxFeeKeyImage;
    return *this;
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        // DAPScoin: previously MoneyRange() was called here. This has been replaced with negative check and boundary wrap check.
        if (it->nValue < 0)
            throw std::runtime_error("CTransaction::GetValueOut() : value out of range : less than 0");

        if ((nValueOut + it->nValue) < nValueOut)
            throw std::runtime_error("CTransaction::GetValueOut() : value out of range : wraps the int64_t boundary");

        if (IsCoinBase() || IsCoinStake() || IsCoinAudit()) nValueOut += it->nValue;
    }
    return nValueOut;
}

bool CTransaction::UsesUTXO(const COutPoint out)
{
    for (const CTxIn in : vin) {
        if (in.prevout == out)
            return true;
    }

    return false;
}

std::list<COutPoint> CTransaction::GetOutPoints() const
{
    std::list<COutPoint> listOutPoints;
    uint256 txHash = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++)
        listOutPoints.emplace_back(COutPoint(txHash, i));
    return listOutPoints;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return (dPriorityInputs + nTxFee * 1000) / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

std::string CTransaction::ToString() const
{
    std::string str;
    //CPubKey pubkey(txPub);
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}
