// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receivecoinsdialog.h"
#include "ui_receivecoinsdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"

#include <QAction>
#include <QClipboard>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QStylePainter>

ReceiveCoinsDialog::ReceiveCoinsDialog(QWidget* parent) : QDialog(parent),
                                                          ui(new Ui::ReceiveCoinsDialog),
                                                          // m_SizeGrip(this),
                                                          model(0)
{
    ui->setupUi(this);


    // context menu actions
    QAction* copyLabelAction = new QAction(tr("Copy label"), this);
    QAction* copyMessageAction = new QAction(tr("Copy message"), this);
    QAction* copyAmountAction = new QAction(tr("Copy amount"), this);

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->setAttribute(Qt::WA_DeleteOnClose);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyMessageAction);
    contextMenu->addAction(copyAmountAction);

    // Show privacy account address
    ui->lineEditAddress->setStyleSheet("border:none; background: transparent; text-align:center;");
    ui->pushButtonCP->setStyleSheet("background:transparent;");
    ui->pushButtonCP->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCP, SIGNAL(clicked()), this, SLOT(copyAddress()));

    //Create privacy account (wallet is unlocked first launch so !pwalletMain->IsLocked() works here)
    if (pwalletMain && !pwalletMain->IsLocked()) {
        CPubKey temp;
        pwalletMain->GetKeyFromPool(temp);
        pwalletMain->CreatePrivacyAccount();
     }

    ui->reqAmount->setValidator(new QRegExpValidator(QRegExp("[0-9]*.[0-9]*"), this));
}

static inline int64_t roundint64(double d)
{
    return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
}

CAmount ReceiveCoinsDialog::getValidatedAmount() {
    double dAmount = ui->reqAmount->text().toDouble();
    if (dAmount < 0.0 || dAmount > Params().MAX_MONEY)
        throw runtime_error("Invalid amount, amount should be < 2.1B DAPS");
    CAmount nAmount = roundint64(dAmount * COIN);
    return nAmount;
}

void ReceiveCoinsDialog::setModel(WalletModel* model)
{
    this->model = model;

    if (model && model->getOptionsModel()) {
        model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        updateDisplayUnit();
        loadAccount();
    }
}

void ReceiveCoinsDialog::loadAccount() {
    //Set reqAddress as the master stealth address
    std::vector<std::string> addrList, accountList;
    CWallet* wl = model->getCWallet();
    QList<QString> stringsList;
    wl->AllMyPublicAddresses(addrList, accountList);
    for(size_t i = 0; i < addrList.size(); i++) {
        bool isDuplicate = false;
        for (size_t i = 0; i < (size_t)ui->reqAddress->count(); i++) {
            if (ui->reqAddress->itemText(i).contains(QString(addrList[i].c_str()), Qt::CaseSensitive)) {
                isDuplicate = true;
                break;
            }
        }
        if (!isDuplicate) {

            stringsList.append(QString(accountList[i].c_str()) + " - " + QString(addrList[i].substr(0, 30).c_str()) + "..." + 
                QString(addrList[i].substr(addrList[i].length() - 30, 30).c_str()));
        }
    }
    ui->reqAddress->addItems(stringsList);
    //Set lineEditAddress to Master Account address for copy to clipboard
    ui->lineEditAddress->setText(QString(addrList[0].substr(0, 30).c_str()) + "..." + 
                QString(addrList[0].substr(addrList[0].length() - 30, 30).c_str()));
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    if (!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    std::vector<std::string> addrList, accountList;
    CWallet* wl = model->getCWallet();
    wl->AllMyPublicAddresses(addrList, accountList);
    int selectedIdx = ui->reqAddress->currentIndex();
    if ((int)addrList.size() > selectedIdx){
        QString address(addrList[selectedIdx].c_str());
        QString label(accountList[selectedIdx].c_str());
        QString reqMes = ui->reqID->text();
        QString strPaymentID = ui->reqID->text();
        if (!strPaymentID.trimmed().isEmpty()) {
            quint64 paymentID = strPaymentID.toULongLong();
            uint64_t id = paymentID;
            std::string integratedAddr;
            if (selectedIdx == 0) {
                wl->ComputeIntegratedPublicAddress(id, "masteraccount", integratedAddr);
            } else {
                wl->ComputeIntegratedPublicAddress(id, accountList[selectedIdx], integratedAddr);
            }
            address = QString(integratedAddr.c_str());
        }

        SendCoinsRecipient info(address, label, getValidatedAmount(), reqMes);
        ReceiveRequestDialog* dialog = new ReceiveRequestDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setModel(model->getOptionsModel());
        dialog->setInfo(info);
        dialog->show();
        clear();
        model->getRecentRequestsTableModel()->addNewRequest(info);
    }

}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void ReceiveCoinsDialog::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void ReceiveCoinsDialog::keyPressEvent(QKeyEvent* event)
{
    if (event->key() == Qt::Key_Return) {
        // press return -> submit form
        if (ui->reqAddress->hasFocus() || ui->reqAmount->hasFocus() || ui->reqID->hasFocus()) {
            event->ignore();
            on_receiveButton_clicked();
            return;
        }
    }

    this->QDialog::keyPressEvent(event);
}

void ReceiveCoinsDialog::copyAddress(){
    std::vector<std::string> addrList, accountList;
    QClipboard *clipboard = QApplication::clipboard();
    CWallet* wl = model->getCWallet();
    wl->AllMyPublicAddresses(addrList, accountList);
    clipboard->setText(QString(addrList[0].c_str()));
}
