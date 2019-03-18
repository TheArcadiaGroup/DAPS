// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2018-2019 The DAPScoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "init.h"
#include "obfuscation.h"
#include "obfuscationconfig.h"
#include "optionsmodel.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "txentry.h"
#include "walletmodel.h"

#include <QAbstractItemDelegate>
#include <QPainter>
#include <QSettings>
#include <QSizePolicy>
#include <QTimer>
#include <QtMath>

#define DECORATION_SIZE 48
#define ICON_OFFSET 16
#define NUM_ITEMS 5

extern CWallet* pwalletMain;

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate() : QAbstractItemDelegate(), unit(BitcoinUnits::DAPS)
    {
    }

    inline void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        QRect mainRect = option.rect;
        mainRect.moveLeft(ICON_OFFSET);
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2 * ypad) / 2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top() + ypad, mainRect.width() - xspace - ICON_OFFSET, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top() + ypad + halfheight, mainRect.width() - xspace, halfheight);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = COLOR_BLACK;
        if (value.canConvert<QBrush>()) {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter, address, &boundingRect);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool()) {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 5, mainRect.top() + ypad + halfheight, 16, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        if (amount < 0) {
            foreground = COLOR_NEGATIVE;
        } else if (!confirmed) {
            foreground = COLOR_UNCONFIRMED;
        } else {
            foreground = COLOR_BLACK;
        }
        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if (!confirmed) {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight | Qt::AlignVCenter, amountText);

        painter->setPen(COLOR_BLACK);
        painter->drawText(amountRect, Qt::AlignLeft | Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
};
#include "overviewpage.moc"

OverviewPage::OverviewPage(QWidget* parent) : QDialog(parent),
                                              ui(new Ui::OverviewPage),
                                              clientModel(0),
                                              walletModel(0),
                                              currentBalance(-1),
                                              currentUnconfirmedBalance(-1),
                                              currentImmatureBalance(-1),
                                              currentZerocoinBalance(-1),
                                              currentUnconfirmedZerocoinBalance(-1),
                                              currentimmatureZerocoinBalance(-1),
                                              currentWatchOnlyBalance(-1),
                                              currentWatchUnconfBalance(-1),
                                              currentWatchImmatureBalance(-1),
                                              txdelegate(new TxViewDelegate()),
                                              filter(0)
{
    nDisplayUnit = 0; // just make sure it's not unitialized
    ui->setupUi(this);

    pingNetworkInterval = new QTimer(this);
    connect(pingNetworkInterval, SIGNAL(timeout()), this, SLOT(tryNetworkBlockCount()));
    pingNetworkInterval->setInterval(3000); pingNetworkInterval->start(); 
    
    pingNetworkInterval = new QTimer();

    initSyncCircle(.8);
    // updateRecentTransactions();
}

void OverviewPage::handleTransactionClicked(const QModelIndex& index)
{
    if (filter)
        emit transactionClicked(filter->mapToSource(index));
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::getPercentage(CAmount nUnlockedBalance, CAmount nZerocoinBalance, QString& sDAPSPercentage, QString& szDAPSPercentage)
{
    int nPrecision = 2;
    double dzPercentage = 0.0;

    if (nZerocoinBalance <= 0){
        dzPercentage = 0.0;
    }
    else{
        if (nUnlockedBalance <= 0){
            dzPercentage = 100.0;
        }
        else{
            dzPercentage = 100.0 * (double)(nZerocoinBalance / (double)(nZerocoinBalance + nUnlockedBalance));
        }
    }

    double dPercentage = 100.0 - dzPercentage;
    
    szDAPSPercentage = "(" + QLocale(QLocale::system()).toString(dzPercentage, 'f', nPrecision) + " %)";
    sDAPSPercentage = "(" + QLocale(QLocale::system()).toString(dPercentage, 'f', nPrecision) + " %)";
    
}

void OverviewPage::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, 
                              const CAmount& zerocoinBalance, const CAmount& unconfirmedZerocoinBalance, const CAmount& immatureZerocoinBalance,
                              const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentZerocoinBalance = zerocoinBalance;
    currentUnconfirmedZerocoinBalance = unconfirmedZerocoinBalance;
    currentimmatureZerocoinBalance = immatureZerocoinBalance;
    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;

    // DAPS labels
    //Cam: Remove immatureBalance from showing on qt wallet (as andrew says)
    ui->labelBalance->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, balance /*- immatureBalance*/, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, unconfirmedBalance, false, BitcoinUnits::separatorAlways));
    ui->labelBalance_2->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, balance /*- immatureBalance*/, false, BitcoinUnits::separatorAlways));

  
    // zDAPS labels
    QString szPercentage = "";
    QString sPercentage = "";
    CAmount nLockedBalance = 0;
    if (pwalletMain) {
        nLockedBalance = pwalletMain->GetLockedCoins();
    }
//    ui->labelLockedBalance->setText(BitcoinUnits::floorHtmlWithUnit(nDisplayUnit, nLockedBalance, false, BitcoinUnits::separatorAlways));

    CAmount nTotalBalance = balance + unconfirmedBalance;
    CAmount nUnlockedBalance = nTotalBalance - nLockedBalance;
    getPercentage(nUnlockedBalance, zerocoinBalance, sPercentage, szPercentage);


    /**
* @author Wang
* @type zerocoin
*/

    // Adjust bubble-help according to AutoMint settings
    QString automintHelp = tr("Current percentage of zDAPS.\nIf AutoMint is enabled this percentage will settle around the configured AutoMint percentage (default = 10%).\n");
    bool fEnableZeromint = GetBoolArg("-enablezeromint", false);
    int nZeromintPercentage = GetArg("-zeromintpercentage", 10);
    if (fEnableZeromint) {
        automintHelp += tr("AutoMint is currently enabled and set to ") + QString::number(nZeromintPercentage) + "%.\n";
        automintHelp += tr("To disable AutoMint add 'enablezeromint=0' in dapscoin.conf.");
    }
    else {
        automintHelp += tr("AutoMint is currently disabled.\nTo enable AutoMint change 'enablezeromint=0' to 'enablezeromint=1' in dapscoin.conf");
    }

    // REMOVE static int cachedTxLocks = 0;

    // REMOVE if (cachedTxLocks != nCompleteTXLocks) {
    // REMOVE     cachedTxLocks = nCompleteTXLocks;
    // REMOVE     ui->listTransactions->update();
    // REMOVE }
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
        ui->labelBalance->setIndent(20);
        ui->labelUnconfirmed->setIndent(20);
}

void OverviewPage::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (model) {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
    if (model && model->getOptionsModel()) {
        // Set up transaction list
        filter = new TransactionFilterProxy();
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getImmatureBalance(),
                   model->getZerocoinBalance(), model->getUnconfirmedZerocoinBalance(), model->getImmatureZerocoinBalance(), 
                   model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance());
        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this, 
                         SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));
    }

    // update the display unit, to not use the default ("DAPS")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if (walletModel && walletModel->getOptionsModel()) {
        nDisplayUnit = walletModel->getOptionsModel()->getDisplayUnit();
        if (currentBalance != -1)
            setBalance(currentBalance, currentUnconfirmedBalance, currentImmatureBalance, currentZerocoinBalance, currentUnconfirmedZerocoinBalance, currentimmatureZerocoinBalance,
                currentWatchOnlyBalance, currentWatchUnconfBalance, currentWatchImmatureBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = nDisplayUnit;

        // REMOVE ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString& warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showBalanceSync(bool fShow){
        ui->labelWalletStatus->setVisible(fShow);
        ui->labelPendingText->setVisible(fShow);
        ui->labelUnconfirmed->setVisible(fShow);
        ui->labelBalanceText->setVisible(fShow);
        isSyncingBalance = fShow;
}

void OverviewPage::showBlockSync(bool fShow)
{
    ui->labelBlockStatus->setVisible(fShow);
    ui->labelBlockOf->setVisible(fShow);
    ui->labelBlocksTotal->setVisible(fShow);

    isSyncingBlocks = fShow;

    ui->labelBlockCurrent->setText(QString::number(clientModel->getNumBlocks()));
    // if (!fShow)
        ui->labelBlockCurrent->setAlignment(fShow? (Qt::AlignRight|Qt::AlignVCenter):(Qt::AlignHCenter|Qt::AlignTop));
}

void OverviewPage::initSyncCircle(float ratioToParent)
{
    animTicker = new QTimer(this);
    animTicker->setInterval(17); //17 mSecs or ~60 fps
    animClock = new QElapsedTimer();
    connect(animTicker, SIGNAL(timeout()), this, SLOT(onAnimTick()));
    animTicker->start(); animClock->start();

    blockAnimSyncCircle = new QWidget(ui->widgetSyncBlocks);
    blockAnimSyncCircle->setStyleSheet("image:url(':/images/syncb')");//"background-image: ./image.png");
    blockAnimSyncCircle->setGeometry(getCircleGeometry(ui->widgetSyncBlocks, ratioToParent));
    blockAnimSyncCircle->show();

    blockSyncCircle = new QWidget(ui->widgetSyncBlocks);
    blockSyncCircle->setStyleSheet("image:url(':/images/syncp')");//"background-image: ./image.png");
    blockSyncCircle->setGeometry(getCircleGeometry(ui->widgetSyncBlocks, ratioToParent));
    blockSyncCircle->show();

    balanceAnimSyncCircle = new QWidget(ui->widgetSyncBalance);
    balanceAnimSyncCircle->setStyleSheet("image:url(':/images/syncb')");//"background-image: ./image.png");
    balanceAnimSyncCircle->setGeometry(getCircleGeometry(ui->widgetSyncBalance, ratioToParent));
    balanceAnimSyncCircle->show();

    balanceSyncCircle = new QWidget(ui->widgetSyncBalance);
    balanceSyncCircle->setStyleSheet("image:url(':/images/syncp')");//"background-image: ./image.png");
    balanceSyncCircle->setGeometry(getCircleGeometry(ui->widgetSyncBalance, ratioToParent));
    balanceSyncCircle->show();
}

void OverviewPage::onAnimTick()
{
    if (isSyncingBlocks){
        moveSyncCircle(blockSyncCircle, blockAnimSyncCircle, 3, 120);
        blockSyncCircle->setStyleSheet("image:url(':/images/syncp')");
        blockAnimSyncCircle->setVisible(true);
    } else {
        blockSyncCircle->setStyleSheet("image:url(':/images/syncb')");
        blockAnimSyncCircle->setVisible(false);
    }
    if (isSyncingBalance){
        moveSyncCircle(balanceSyncCircle, balanceAnimSyncCircle, 3, -100, 130);
        balanceSyncCircle->setStyleSheet("image:url(':/images/syncp')");
        balanceAnimSyncCircle->setVisible(true);
    } else {
        balanceSyncCircle->setStyleSheet("image:url(':/images/syncb')");
        balanceAnimSyncCircle->setVisible(false);
    }
    showBalanceSync(currentUnconfirmedBalance>0);
}

void OverviewPage::moveSyncCircle(QWidget* anchor, QWidget* animated, int deltaRadius, float degreesPerSecond, float angleOffset) //deltaRad in px
{
    auto centerX = anchor->parentWidget()->width()/10;  //center of anchor
    auto centerY = anchor->parentWidget()->height()/10;
    auto angle = float(animClock->elapsed()/*%3600*/)*degreesPerSecond/1000;
    angle = qDegreesToRadians(angle+angleOffset); //rotation angle from time elapsed
    auto newX = centerX+deltaRadius*qCos(angle); //delta position plus anchor position
    auto newY = centerY+deltaRadius*qSin(angle);

    animated->setGeometry(newX, newY, anchor->width(), anchor->height());
}

QRect OverviewPage::getCircleGeometry(QWidget* parent, float ratioToParent)
{
    auto width = parent->width()*ratioToParent;
    auto height = parent->height()*ratioToParent;
    auto x = (parent->width()-width)/2;
    auto y = (parent->height()-height)/2;
    return QRect(x,y,width,height);
}

void OverviewPage::updateTotalBlocksLabel(){
    ui->labelBlocksTotal->setText(QString::number(networkBlockCount));
}

int OverviewPage::tryNetworkBlockCount(){
    try{
        if (vNodes.size()>=1){
            int highestCount = 0;
            for (CNode* node : vNodes)
                if (node->nStartingHeight>highestCount)
                    highestCount = node->nStartingHeight;
            if (highestCount>550){
                networkBlockCount = highestCount; 
                updateTotalBlocksLabel();
                return highestCount;
            }
        }
    }catch(int err_code)
    {
         //QDebug()<<endl<<"Error: "+QString::number(err_code)<<endl;
    }
    return -1;
}

void OverviewPage::updateRecentTransactions(){
    QLayoutItem* item;
    while ( ( item = ui->verticalLayoutRecent->takeAt( 0 ) ) != NULL )
    {
        delete item->widget();
        delete item;
    }
    auto txs = WalletUtil::getTXs(pwalletMain);

    for (int i = 0; i< (txs.size()>5)? 5:txs.size(); i++){
        TxEntry* entry = new TxEntry(this);
        ui->verticalLayoutRecent->addWidget(entry);
        entry->setData(txs[i]["date"], txs[i]["address"] , txs[i]["amount"], txs[i]["ID"], txs[i]["type"]);
    }

    ui->label_4->setVisible(txs.size());
}