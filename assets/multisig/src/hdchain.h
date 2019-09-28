// Copyright (c) 2014-2018 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
#ifndef BITCOIN_HDCHAIN_H
#define BITCOIN_HDCHAIN_H

#include "key.h"
#include "sync.h"
#include "pubkey.h"

/* simple HD chain data model */
class CHDChain
{
private:
    static const int CURRENT_VERSION = 1;
    int nVersion;

    uint256 id;

    bool fCrypted;

    SecureVector vchSeed;
    SecureVector vchMnemonic;
    SecureVector vchMnemonicPassphrase;

public:

    CHDChain() { SetNull(); }
    CHDChain(const CHDChain& other) :
        nVersion(other.nVersion),
        id(other.id),
        fCrypted(other.fCrypted),
        vchSeed(other.vchSeed),
        vchMnemonic(other.vchMnemonic),
        vchMnemonicPassphrase(other.vchMnemonicPassphrase)
        {}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(this->nVersion);
        READWRITE(id);
        READWRITE(fCrypted);
        READWRITE(vchSeed);
        READWRITE(vchMnemonic);
        READWRITE(vchMnemonicPassphrase);
    }

    void swap(CHDChain& first, CHDChain& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.nVersion, second.nVersion);
        swap(first.id, second.id);
        swap(first.fCrypted, second.fCrypted);
        swap(first.vchSeed, second.vchSeed);
        swap(first.vchMnemonic, second.vchMnemonic);
        swap(first.vchMnemonicPassphrase, second.vchMnemonicPassphrase);
    }
    CHDChain& operator=(CHDChain from)
    {
        swap(*this, from);
        return *this;
    }

    bool SetNull();
    bool IsNull() const;

    void SetCrypted(bool fCryptedIn);
    bool IsCrypted() const;

    void Debug(const std::string& strName) const;

    bool SetMnemonic(const SecureVector& vchMnemonic, const SecureVector& vchMnemonicPassphrase, bool fUpdateID);
    bool SetMnemonic(const SecureString& ssMnemonic, const SecureString& ssMnemonicPassphrase, bool fUpdateID);
    bool GetMnemonic(SecureVector& vchMnemonicRet, SecureVector& vchMnemonicPassphraseRet) const;
    bool GetMnemonic(SecureString& ssMnemonicRet, SecureString& ssMnemonicPassphraseRet) const;

    bool SetSeed(const SecureVector& vchSeedIn, bool fUpdateID);
    SecureVector GetSeed() const;

    uint256 GetID() const { return id; }

    uint256 GetSeedHash();
    void DeriveChildExtKey(uint32_t nAccountIndex, bool fInternal, uint32_t nChildIndex, CExtKey& extKeyRet);
};

/* hd pubkey data model */
class CHDPubKey
{
private:
    static const int CURRENT_VERSION = 1;
    int nVersion;

public:
    CExtPubKey extPubKey;
    uint256 hdchainID;
    uint32_t nAccountIndex;
    uint32_t nChangeIndex;

    CHDPubKey() : nVersion(CHDPubKey::CURRENT_VERSION), nAccountIndex(0), nChangeIndex(0) {}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(this->nVersion);
        READWRITE(extPubKey);
        READWRITE(hdchainID);
        READWRITE(nAccountIndex);
        READWRITE(nChangeIndex);
    }

    std::string GetKeyPath() const;
};

#endif // BITCOIN_HDCHAIN_H
