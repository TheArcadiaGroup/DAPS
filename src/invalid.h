// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPScoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DAPScoin_INVALID_H
#define DAPScoin_INVALID_H

#endif //DAPScoin_INVALID_H

#include <univalue/include/univalue.h>
#include <primitives/transaction.h>

namespace invalid_out
{
    extern std::set<CBigNum> setInvalidSerials;
    extern std::set<COutPoint> setInvalidOutPoints;

    UniValue read_json(const std::string& jsondata);

    bool ContainsOutPoint(const COutPoint& out);
    bool ContainsSerial(const CBigNum& bnSerial);
    bool LoadOutpoints();
    bool LoadSerials();
}
