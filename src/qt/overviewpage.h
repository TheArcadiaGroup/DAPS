// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OVERVIEWPAGE_H
#define BITCOIN_QT_OVERVIEWPAGE_H

#include "amount.h"

#include <QWidget>
#include <QTimer>
#include <QElapsedTimer>
#include <QDialog>
#include <QSizeGrip>

class ClientModel;
class TransactionFilterProxy;
class TxViewDelegate;
class WalletModel;
// class BitcoinGUI;

namespace Ui
{
class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QDialog
{
    Q_OBJECT

public:
    explicit OverviewPage(QWidget* parent = 0);
    ~OverviewPage();

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);
    void showBlockSync(bool fShow);
    void showBalanceSync(bool fShow);
    // void bitcoinGUIInstallEvent(BitcoinGUI *gui);
    

    QTimer* animTicker;
    QElapsedTimer* animClock;

public slots:
    void setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, 
                    const CAmount& zerocoinBalance, const CAmount& unconfirmedZerocoinBalance, const CAmount& immatureZerocoinBalance,
                    const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);
    void onAnimTick();   
    void updateTotalBlocksLabel();
    int tryNetworkBlockCount();
    void updateRecentTransactions();
    void refreshRecentTransactions();
    void setSpendableBalance(bool isStaking);
    void showBlockCurrentHeight();

signals:
    void transactionClicked(const QModelIndex& index);

private:
    QTimer* timer;
    QTimer* pingNetworkInterval;
    Ui::OverviewPage* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;
    int networkBlockCount;
    CAmount currentBalance;
    CAmount currentUnconfirmedBalance;
    CAmount currentImmatureBalance;
    CAmount currentZerocoinBalance;
    CAmount currentUnconfirmedZerocoinBalance;
    CAmount currentimmatureZerocoinBalance;
    CAmount currentWatchOnlyBalance;
    CAmount currentWatchUnconfBalance;
    CAmount currentWatchImmatureBalance;
    int nDisplayUnit;
    void getPercentage(CAmount nTotalBalance, CAmount nZerocoinBalance, QString& sDAPSPercentage, QString& szDAPSPercentage);

    TxViewDelegate* txdelegate;
    TransactionFilterProxy* filter;

    QWidget* blockSyncCircle;
    // QSizeGrip m_SizeGrip;
    QWidget* blockAnimSyncCircle;
    bool isSyncingBlocks=true;
    QWidget* balanceSyncCircle;
    QWidget* balanceAnimSyncCircle;
    bool isSyncingBalance=true;

    // virtual void resizeEvent(QResizeEvent* event);
    void initSyncCircle(float percentOfParent);
    void moveSyncCircle(QWidget* anchor, QWidget* animated, int deltaRadius, float degreesPerSecond, float angleOffset=0);
    QRect getCircleGeometry(QWidget* parent, float ratioToParent);

private slots:
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex& index);
    void updateAlerts(const QString& warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
