// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2019 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

#include <math.h>

unsigned int N_BITS = 0x1e1ffff0;
bool CheckPoAMiningBlockHeight(const CBlockHeader* pblock)
{
    return false;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock)
{
    if (N_BITS != 0 && pblock->IsPoABlockByVersion()) {
        return N_BITS;
    }
    /* current difficulty formula, dapscoin - DarkGravity v3, written by Evan Duffield - evan@dashpay.io */
    const CBlockIndex* BlockLastSolved = pindexLast;
    const CBlockIndex* BlockReading = pindexLast;
    int64_t nActualTimespan = 0;
    int64_t LastBlockTime = 0;
    int64_t PastBlocksMin = 24;
    int64_t PastBlocksMax = 24;
    int64_t CountBlocks = 0;
    uint256 PastDifficultyAverage;
    uint256 PastDifficultyAveragePrev;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || BlockLastSolved->nHeight < PastBlocksMin) {
        return Params().ProofOfWorkLimit().GetCompact();
    }

    if (pindexLast->nHeight > Params().LAST_POW_BLOCK()) {
        uint256 bnTargetLimit = (~uint256(0) >> 24);
        int64_t nTargetSpacing = 60;
        int64_t nTargetTimespan = 60 * 40;

        //finding last PoS block
        CBlockIndex* pLastPoS = pindexLast->pprev;
        while (!pLastPoS->IsProofOfStake() && pLastPoS->nHeight > Params().LAST_POW_BLOCK()) {
            pLastPoS = pLastPoS->pprev;
        }
        int64_t nActualSpacing = 0;
        //ig
        if (pindexLast->nHeight != 0)
            nActualSpacing = pindexLast->GetBlockTime() - pLastPoS->GetBlockTime();

        if (nActualSpacing < 0)
            nActualSpacing = 1;

        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        uint256 bnNew;
        if (pindexLast->nHeight < 24900) {
            bnNew.SetCompact(pindexLast->nBits);
        } else {
            if (pindexLast->IsProofOfStake()) {
                bnNew.SetCompact(pindexLast->nBits);    
            } else {
                bnNew.SetCompact(pLastPoS->nBits);
            }
        }

        int64_t nInterval = nTargetTimespan / nTargetSpacing;
        bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
        bnNew /= ((nInterval + 1) * nTargetSpacing);

        if (bnNew <= 0 || bnNew > bnTargetLimit)
            bnNew = bnTargetLimit;

        return bnNew.GetCompact();
    }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) {
            break;
        }
        CountBlocks++;

        if (CountBlocks <= PastBlocksMin) {
            if (CountBlocks == 1) {
                PastDifficultyAverage.SetCompact(BlockReading->nBits);
            } else {
                PastDifficultyAverage = ((PastDifficultyAveragePrev * CountBlocks) + (uint256().SetCompact(BlockReading->nBits))) / (CountBlocks + 1);
            }
            PastDifficultyAveragePrev = PastDifficultyAverage;
        }

        if (LastBlockTime > 0) {
            int64_t Diff = (LastBlockTime - BlockReading->GetBlockTime());
            nActualTimespan += Diff;
        }
        LastBlockTime = BlockReading->GetBlockTime();

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    uint256 bnNew(PastDifficultyAverage);

    int64_t _nTargetTimespan = CountBlocks * Params().TargetSpacing();

    if (nActualTimespan < _nTargetTimespan / 3)
        nActualTimespan = _nTargetTimespan / 3;
    if (nActualTimespan > _nTargetTimespan * 3)
        nActualTimespan = _nTargetTimespan * 3;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= _nTargetTimespan;

    if (bnNew > Params().ProofOfWorkLimit()) {
        bnNew = Params().ProofOfWorkLimit();
    }

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;

    if (Params().SkipProofOfWorkCheck())
        return true;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > Params().ProofOfWorkLimit())
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget)
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

uint256 GetBlockProof(const CBlockIndex& block)
{
    uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

//If blockheight = -1, the to-be-checked block is not included yet in the chain, otherwise, that is the height of the poa block
bool CheckPoAContainRecentHash(const CBlock& block)
{
    //block.Merkle
    CBlockIndex* currentTip = mapBlockIndex[block.hashPrevBlock];
    if (!currentTip) {
        return error("CheckPoAContainRecentHash() : Previous block not found");
    }
    //Find the previous PoA block
    CBlockIndex* pindex = currentTip;
    while (pindex->nHeight >= Params().START_POA_BLOCK()) {
        if (pindex->GetBlockHeader().IsPoABlockByVersion()) {
            break;
        }
        pindex = pindex->pprev;
    }
    bool ret = true;
    if (pindex->nHeight <= Params().START_POA_BLOCK()) {
        //this is the first PoA block ==> check all PoS blocks from LAST_POW_BLOCK up to currentHeight - POA_BLOCK_PERIOD - 1 inclusive
        int index = 0;
        for (size_t i = Params().LAST_POW_BLOCK() + 1; i <= Params().LAST_POW_BLOCK() + block.posBlocksAudited.size(); i++) {
            PoSBlockSummary pos = block.posBlocksAudited.at(index);
            CBlockIndex* pidxInChain = mapBlockIndex[pos.hash];
            if (!pidxInChain) {
                return error("CheckPoAContainRecentHash() : Audited blocks not found");
            }
            if (pos.hash != pidxInChain->GetBlockHash() || pos.nTime != pidxInChain->nTime || pos.height != (uint32_t)pidxInChain->nHeight) {
                ret = false;
                break;
            }
            CBlockIndex* p = mapBlockIndex[pos.hash];
            bool auditResult = ReVerifyPoSBlock(p);
            if (!auditResult) {
                if (pos.nTime) {
                    ret = false;
                    break;
                }
            }
            index++;
        }
    } else {
        if (pindex->nHeight >= Params().START_POA_BLOCK()) {
            CBlock prevPoablock;
            CBlockIndex* pblockindex = pindex;
            if (!ReadBlockFromDisk(prevPoablock, pblockindex))
                throw runtime_error("Can't read block from disk");
            PoSBlockSummary lastAuditedPoSBlockInfo = prevPoablock.posBlocksAudited.back();
            uint256 lastAuditedPoSHash = lastAuditedPoSBlockInfo.hash;
            if (mapBlockIndex.count(lastAuditedPoSHash) < 1) {
                return error("CheckPoAContainRecentHash() : Audited blocks not found");
            }
            CBlockIndex* piterator = mapBlockIndex[lastAuditedPoSHash]->pnext;
            uint32_t idxOfPoSInfo = 0;
            if (!piterator) {
                //check whether chainActive has
                if (mapBlockIndex[lastAuditedPoSHash]->nHeight + 1 > chainActive.Height()) {
                    return error("CheckPoAContainRecentHash() : PoS block %s not found", lastAuditedPoSHash.GetHex());
                }
                piterator = chainActive[mapBlockIndex[lastAuditedPoSHash]->nHeight + 1];
                if (!piterator)
                    return error("CheckPoAContainRecentHash() : PoS block %s not found", lastAuditedPoSHash.GetHex());
                if (piterator->pprev == NULL || piterator->pprev->GetBlockHash() != lastAuditedPoSHash) {
                    return error("CheckPoAContainRecentHash() : PoS block %s not found", lastAuditedPoSHash.GetHex());
                }
            }
            while (piterator->nHeight <= (uint32_t)currentTip->nHeight && idxOfPoSInfo < block.posBlocksAudited.size()) {
                if (!piterator->GetBlockHeader().IsPoABlockByVersion() && piterator->nHeight > Params().LAST_POW_BLOCK()) {
                    PoSBlockSummary pos = block.posBlocksAudited[idxOfPoSInfo];
                    CBlockIndex* posAudited = piterator;
                    if (pos.hash == *(posAudited->phashBlock) && pos.height == (uint32_t)posAudited->nHeight && pos.nTime == posAudited->GetBlockTime()) {
                        idxOfPoSInfo++;
                    } else {
                        //The PoA block is not satisfied the constraint
                        ret = false;
                        break;
                    }

                    CBlockIndex* p = mapBlockIndex[pos.hash];
                    bool auditResult = ReVerifyPoSBlock(p);
                    if (!auditResult) {
                        if (pos.nTime) {
                            ret = false;
                            break;
                        }
                    }
                }
                uint256 h = piterator->GetBlockHash();
                piterator = piterator->pnext;

                if (!piterator) {
                    if (mapBlockIndex[h]->nHeight + 1 > chainActive.Height()) {
                        return error("CheckPoAContainRecentHash() : PoS block %s not found", lastAuditedPoSHash.GetHex());
                    }
                    piterator = chainActive[mapBlockIndex[h]->nHeight + 1];
                    if (!piterator)
                        return error("CheckPoAContainRecentHash() : PoS block %s not found", h.GetHex());
                    if (piterator->pprev == NULL || piterator->pprev->GetBlockHash() != h) {
                        return error("CheckPoAContainRecentHash() : PoS block %s not found", h.GetHex());
                    }
                }
            }

            if (idxOfPoSInfo != block.posBlocksAudited.size()) {
                //Not all PoS Blocks in PoA block have been checked, not satisfied
                ret = false;
            }
        } else {
            ret = block.hashPrevPoABlock.IsNull();
        }
    }
    return ret;
}

bool CheckNumberOfAuditedPoSBlocks(const CBlock& block)
{
    if (block.posBlocksAudited.size() < (size_t)Params().MIN_NUM_POS_BLOCKS_AUDITED()) {
        return false;
    }
    return true;
}

//Check whether the block is successfully mined and the mined hash satisfy the difficulty
bool CheckPoABlockMinedHash(const CBlockHeader& block)
{
    const uint256 minedHash = block.minedHash; //block.ComputeMinedHash();
    if (minedHash == block.minedHash) {
        //Check minedHash satisfy difficulty based on nbits
        bool fNegative;
        bool fOverflow;
        uint256 bnTarget;

        //As of now, there is no PoA miner, this will let all emulated PoA blocks bypass the check
        if (Params().SkipProofOfWorkCheck() || Params().NetworkID() == CBaseChainParams::TESTNET)
            return true;

        //The current mainnet is at 10800 blocks, this check will ignore these first blocks
        if (mapBlockIndex.count(block.hashPrevBlock) != 0) {
            if (CheckPoAMiningBlockHeight(&block)) {
                return true;
            }
        }

        bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
        LogPrintf("Target:%s, minedHash:%s", bnTarget.GetHex(), minedHash.GetHex());

        // Check proof of work matches claimed amount
        if (minedHash > bnTarget) {
            LogPrintf("Block mined hash not satisfied");
            return error("CheckProofOfWork() : hash doesn't match nBits");
        }

        return true;
    }
    return false;
}

//A PoA block should contains previous PoA block hash
bool CheckPrevPoABlockHash(const CBlockHeader& block)
{
    CBlockIndex* currentTip = mapBlockIndex[block.hashPrevBlock];
    if (!currentTip) {
        return error("CheckPoAContainRecentHash() : Previous block not found");
    }
    //Find the previous PoA block
    CBlockIndex* pindex = currentTip;
    while (pindex->nHeight > Params().START_POA_BLOCK()) {
        if (pindex->GetBlockHeader().IsPoABlockByVersion()) {
            break;
        }
        pindex = pindex->pprev;
    }
    bool ret = false;

    if (pindex->nHeight > Params().START_POA_BLOCK()) {
        CBlockHeader header = pindex->GetBlockHeader();
        uint256 poaBlockHash = header.GetHash();
        if (poaBlockHash == block.hashPrevPoABlock) {
            ret = true;
        }
    } else {
        //This is the first poa block ==> previous poa hash = 0
        ret = block.hashPrevPoABlock.IsNull();
    }

    return ret;
}

//Check whether the poa merkle root is correctly computed
bool CheckPoAMerkleRoot(const CBlock& block, bool* fMutate)
{
    uint256 expected = block.BuildPoAMerkleTree(fMutate);
    if (expected == block.hashPoAMerkleRoot) {
        return true;
    }
    return false;
}

//A PoA block cannot contain information of any PoA block information (hash, height, timestamp)
bool CheckPoABlockNotContainingPoABlockInfo(const CBlock& block)
{
    uint32_t numOfPoSBlocks = block.posBlocksAudited.size();
    for (uint32_t i = 0; i < numOfPoSBlocks; i++) {
        PoSBlockSummary pos = block.posBlocksAudited.at(i);
        uint256 hash = pos.hash;
        if (mapBlockIndex.count(hash) == 0) {
            return false;
        }
        CBlockIndex* pblockindex = mapBlockIndex[hash];
        CBlockHeader header = pblockindex->GetBlockHeader();
        if (header.IsPoABlockByVersion()) {
            return false;
        }
    }
    return true;
}

bool CheckPoAblockTime(const CBlock& block)
{
    bool ret = false;

    if (block.hashPrevPoABlock.IsNull()) {
        ret = true;
    } else {
        LogPrint("debug", "%s: Previous PoA block hash %s\n", __func__, block.hashPrevPoABlock.GetHex());
        if (mapBlockIndex.count(block.hashPrevPoABlock) != 0) {
            CBlockIndex* pindex = mapBlockIndex[block.hashPrevPoABlock];
            uint32_t prevPoATime = pindex->nTime;
            if (block.nTime > prevPoATime && (block.nTime - pindex->nTime >= (uint32_t)Params().POA_BLOCK_TIME())) {
                ret = true;
            }
            LogPrint("debug", "%s: PoA Block time: %d, Previous: %d, Current: %d, Distance: %d\n", __func__,
                Params().POA_BLOCK_TIME(), prevPoATime, block.nTime, block.nTime - pindex->nTime);
        } else {
            LogPrint("debug", "%s: Cannot find block hash %s\n", __func__, block.hashPrevPoABlock.GetHex());
        }
    }
    return ret;
}

bool CheckPoABlockNotAuditingOverlap(const CBlock& block)
{
    bool ret = false;

    if (block.hashPrevPoABlock.IsNull()) {
        //First PoA block
        LogPrint("debug", "%s: First PoA Block Hash: %s\n", __func__, block.GetHash().GetHex());
        ret = true;
    } else {
        if (mapBlockIndex.count(block.hashPrevPoABlock) != 0) {
            CBlockIndex* pPrevPoAIndex = mapBlockIndex[block.hashPrevPoABlock];
            CBlock prevPoablock;
            if (!ReadBlockFromDisk(prevPoablock, pPrevPoAIndex))
                throw runtime_error("Can't read block from disk");
            ret = true;
            for (size_t i = 0; i < block.posBlocksAudited.size(); i++) {
                bool isAlreadyAudited = false;
                for (size_t j = 0; j < prevPoablock.posBlocksAudited.size(); j++) {
                    if (prevPoablock.posBlocksAudited[j].hash == block.posBlocksAudited[i].hash && prevPoablock.posBlocksAudited[j].nTime == block.posBlocksAudited[i].nTime && prevPoablock.posBlocksAudited[j].height == block.posBlocksAudited[i].height) {
                        isAlreadyAudited = true;
                        LogPrint("debug", "%s: PoA Block Hash: %s, is already auditted by Block %s\n", __func__,
                            block.posBlocksAudited[i].hash.GetHex(),
                            prevPoablock.GetHash().GetHex());
                        break;
                    }
                }

                if (isAlreadyAudited) {
                    ret = false;
                    break;
                }
            }
        }
    }

    return ret;
}
