// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIP39_H
#define BITCOIN_BIP39_H

#include "allocators.h"

class CMnemonic
{
public:
    static SecureString Generate(int strength);    // strength in bits
    static SecureString FromData(const SecureVector& data, int len);
    static bool Check(SecureString mnemonic);
    // passphrase must be at most 256 characters or code may crash
    static void ToSeed(SecureString mnemonic, SecureString passphrase, SecureVector& seedRet);
};

#endif
