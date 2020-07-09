// Copyright (c) 2014-2019 The Dash Core developers
// Copyright (c) 2019 The BitGreen Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <governance/governance.h>
#include <masternodes/notificationinterface.h>
#include <masternodes/payments.h>
#include <masternodes/sync.h>
#include <validation.h>

#include <special/deterministicmns.h>
#include <special/mnauth.h>

#include <llmq/quorums.h>
#include <llmq/quorums_chainlocks.h>
#include <llmq/quorums_instantsend.h>
#include <llmq/quorums_dkgsessionmgr.h>

#include <util/init.h>

CMNNotificationInterface* g_mn_notification_interface = nullptr;

void CMNNotificationInterface::InitializeCurrentBlockTip()
{
    LOCK(cs_main);
    SynchronousUpdatedBlockTip(ChainActive().Tip(), nullptr, ::ChainstateActive().IsInitialBlockDownload());
    UpdatedBlockTip(ChainActive().Tip(), nullptr, ::ChainstateActive().IsInitialBlockDownload());
}

void CMNNotificationInterface::AcceptedBlockHeader(const CBlockIndex *pindexNew)
{
    llmq::chainLocksHandler->AcceptedBlockHeader(pindexNew);
    masternodeSync.AcceptedBlockHeader(pindexNew);
}

void CMNNotificationInterface::NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload)
{
    masternodeSync.NotifyHeaderTip(pindexNew, fInitialDownload, connman);
}

void CMNNotificationInterface::SynchronousUpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload)
{
    if (pindexNew == pindexFork) // blocks were disconnected without any new ones
        return;

    deterministicMNManager->UpdatedBlockTip(pindexNew);
}

void CMNNotificationInterface::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload)
{
    if (pindexNew == pindexFork) // blocks were disconnected without any new ones
        return;
    masternodeSync.UpdatedBlockTip(pindexNew, fInitialDownload, connman);

    if (fInitialDownload)
        return;

    if (fLiteMode)
        return;

    llmq::chainLocksHandler->UpdatedBlockTip(pindexNew);

    governance.UpdatedBlockTip(pindexNew, connman);
    llmq::quorumManager->UpdatedBlockTip(pindexNew, fInitialDownload);
    llmq::quorumDKGSessionManager->UpdatedBlockTip(pindexNew, fInitialDownload);
}

void CMNNotificationInterface::BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindex)
{
}

void CMNNotificationInterface::BlockDisconnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexDisconnected)
{
}

void CMNNotificationInterface::NotifyMasternodeListChanged(bool undo, const CDeterministicMNList& oldMNList, const CDeterministicMNListDiff& diff)
{
    CMNAuth::NotifyMasternodeListChanged(undo, oldMNList, diff, connman);
    governance.UpdateCachesAndClean();
}

void CMNNotificationInterface::NotifyChainLock(const CBlockIndex* pindex)
{
}


