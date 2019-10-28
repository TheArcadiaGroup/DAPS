// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sendcoinsdialog.h"
#include "ui_sendcoinsdialog.h"

#include "addresstablemodel.h"
#include "askpassphrasedialog.h"
#include "bitcoinunits.h"
#include "clientmodel.h"
#include "coincontroldialog.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "sendcoinsentry.h"
#include "walletmodel.h"

#include "base58.h"
#include "coincontrol.h"
#include "ui_interface.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "2faconfirmdialog.h"

#include <regex>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QDateTime>
#include <QDebug>


SendCoinsDialog::SendCoinsDialog(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                                    ui(new Ui::SendCoinsDialog),
                                                    clientModel(0),
                                                    // m_SizeGrip(this),
                                                    model(0),
                                                    fNewRecipientAllowed(true)
{
    ui->setupUi(this);

    addEntry();

    connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));

    // #HIDE multisend
    ui->addButton->setVisible(false);
}

void SendCoinsDialog::setClientModel(ClientModel* clientModel)
{
    this->clientModel = clientModel;

    if (clientModel) {
    }
}

void SendCoinsDialog::setModel(WalletModel* model)
{
    this->model = model;

    if (model && model->getOptionsModel()) {
        for (int i = 0; i < ui->entries->count(); ++i) {
            SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if (entry) {
                entry->setModel(model);
            }
        }

        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this,
            SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));
    }
}

void SendCoinsDialog::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, 
                              const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForAnonymizationOnly) {
        ui->labelBalance->setText("Locked; Hidden");
    } else {
        ui->labelBalance->setText(BitcoinUnits::formatHtmlWithUnit(0, balance, false, BitcoinUnits::separatorAlways));
    }
}

SendCoinsDialog::~SendCoinsDialog(){
    delete ui;
}

void SendCoinsDialog::on_sendButton_clicked(){
    if (!ui->entries->count()) 
        return;

    SendCoinsEntry* form = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
    SendCoinsRecipient recipient = form->getValue();
    QString address = recipient.address;
    bool isValidAddresss = (regex_match(address.toStdString(), regex("[a-zA-z0-9]+")))&&(address.length()==99||address.length()==110);
    bool isValidAmount = ((recipient.amount>0) && (recipient.amount<2100000000));

    form->errorAddress(isValidAddresss);
    form->errorAmount(isValidAmount);

    if (!isValidAddresss) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Invalid Address");
        msgBox.setText("Invalid address entered. Please make sure you are sending to a Stealth Address.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.exec();
        return;
    }

    if (!isValidAmount) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Invalid Amount");
        msgBox.setText("Invalid amount entered. Please enter an amount less than 2.1B DAPS.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.exec();
        return;
    }

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Are You Sure?", "Are you sure you would like to send this transaction?", QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes) {
    } else {
        return;
    }

    bool nStaking = (nLastCoinStakeSearchInterval > 0);

    if (nStaking) {
        CAmount spendable = pwalletMain->GetSpendableBalance();
        if (!(recipient.amount <= nReserveBalance && recipient.amount <= spendable)) {
            if (recipient.amount > spendable) {
                QMessageBox msgBox;
                msgBox.setWindowTitle("Insufficient Spendable Funds!");
                msgBox.setText("Insufficient spendable funds. Send with smaller amount or wait for your coins become mature");
                msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                msgBox.setIcon(QMessageBox::Information);
                msgBox.exec();
            } else if (recipient.amount > nReserveBalance) {
                QMessageBox msgBox;
                msgBox.setWindowTitle("Insufficient Reserve Funds!");
                msgBox.setText("Insufficient reserve funds. Send with smaller amount or turn off staking mode.");
                msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                msgBox.setIcon(QMessageBox::Information);
                msgBox.exec();
            }
            return;
        }
    }

    send_address = recipient.address;
    send_amount = recipient.amount;
    bool status = pwalletMain->Read2FA();
    if (!status) {
        sendTx();
        return;
    }
    uint lastTime = pwalletMain->Read2FALastTime();
    uint period = pwalletMain->Read2FAPeriod();
    QDateTime current = QDateTime::currentDateTime();
    uint diffTime = current.toTime_t() - lastTime;
    if (diffTime <= period * 24 * 60 * 60)
        sendTx();
    else {
        TwoFAConfirmDialog codedlg;
        codedlg.setWindowTitle("2FA Code Verification");
        codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&codedlg, SIGNAL(finished (int)), this, SLOT(dialogIsFinished(int)));
        codedlg.exec();
    }
}

void SendCoinsDialog::sendTx() {
    CWalletTx resultTx; 
    bool success = false;
    try {
        success = pwalletMain->SendToStealthAddress(
            send_address.toStdString(),
            send_amount,
            resultTx,
            false
        );
    } catch (const std::exception& err) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Transaction Creation Error");
        msgBox.setText(QString(err.what()));
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.exec();
        return;
    }

    if (success){
        WalletUtil::getTx(pwalletMain, resultTx.GetHash());
        QString txhash = resultTx.GetHash().GetHex().c_str();
        QMessageBox msgBox;
        QPushButton *copyButton = msgBox.addButton(tr("Copy"), QMessageBox::ActionRole);
        copyButton->setStyleSheet("background:transparent;");
        copyButton->setIcon(QIcon(":/icons/editcopy"));
        msgBox.setWindowTitle("Transaction Initialized");
        msgBox.setText("Transaction initialized.\n\n" + txhash);
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Information);
        msgBox.exec();

        if (msgBox.clickedButton() == copyButton) {
        //Copy txhash to clipboard
        GUIUtil::setClipboard(txhash);
        }
    }
}

void SendCoinsDialog::dialogIsFinished(int result) {
   if(result == QDialog::Accepted){
        sendTx();
   }
}

SendCoinsEntry* SendCoinsDialog::addEntry()
{
    SendCoinsEntry* entry = new SendCoinsEntry(this);
    entry->setModel(model);
    ui->entries->addWidget(entry);

    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if (bar)
        bar->setSliderPosition(bar->maximum());
    return entry;
}
