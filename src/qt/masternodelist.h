#ifndef MASTERNODELIST_H
#define MASTERNODELIST_H

#include "guiutil.h"
#include "masternode.h"
#include "platformstyle.h"
#include "sync.h"
#include "togglebutton.h"
#include "util.h"

#include <QMenu>
#include <QTimer>
#include <QWidget>
#include <QDialog>
#include <QTimer>
#include <QSizeGrip>

#define MY_MASTERNODELIST_UPDATE_SECONDS 60
#define MASTERNODELIST_UPDATE_SECONDS 15
#define MASTERNODELIST_FILTER_COOLDOWN_SECONDS 3

class BitcoinGUI;

namespace Ui
{
class MasternodeList;
}

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Masternode Manager page widget */
class MasternodeList : public QDialog
{
    Q_OBJECT

public:
    explicit MasternodeList(QWidget* parent = 0);
    ~MasternodeList();

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);
    void StartAlias(std::string strAlias);
    void StartAll(std::string strCommand = "start-all");
    void bitcoinGUIInstallEvent(BitcoinGUI *gui);

private:
    QMenu* contextMenu;
    int64_t nTimeFilterUpdated;
    bool fFilterUpdated;

public Q_SLOTS:
    void updateMyMasternodeInfo(QString strAlias, QString strAddr, CMasternode* pmn);
    void updateMyNodeList(bool fForce = false);

Q_SIGNALS:

private:
    QTimer* timer;
    QTimer* refreshPageTimer = new QTimer();
    Ui::MasternodeList* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;
    CCriticalSection cs_mnlistupdate;
    QString strCurrentFilter;
    QSizeGrip m_SizeGrip;
    virtual void resizeEvent(QResizeEvent* event);

private Q_SLOTS:
    void showContextMenu(const QPoint&);
    void on_startButton_clicked();
    void on_startAllButton_clicked();
    void on_startMissingButton_clicked();
    void on_tableWidgetMyMasternodes_itemSelectionChanged();
    void on_UpdateButton_clicked();
};
#endif // MASTERNODELIST_H
