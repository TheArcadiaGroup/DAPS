// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The DAPScoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cosigntransaction.h"
#include "ui_cosigntransaction.h"

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


CoSignTransaction::CoSignTransaction(QWidget* parent) : QDialog(parent),
                                                    ui(new Ui::CoSignTransaction),
                                                    clientModel(0),
                                                    // m_SizeGrip(this),
                                                    model(0)
{
    ui->setupUi(this);
    connect(ui->sendButton, SIGNAL(clicked()), this, SLOT(cosignTransaction()));
}

void CoSignTransaction::setClientModel(ClientModel* clientModel)
{
    this->clientModel = clientModel;

    if (clientModel) {
    }
}

void CoSignTransaction::setModel(WalletModel* model)
{
    this->model = model;
    if (model && model->getOptionsModel()) {
        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this,
                SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));
    }
}

void CoSignTransaction::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                                   const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForAnonymizationOnly) {
        ui->labelBalance->setText("Locked; Hidden");
    } else {
        ui->labelBalance->setText(BitcoinUnits::formatHtmlWithUnit(0, balance, false, BitcoinUnits::separatorAlways));
    }
}

CoSignTransaction::~CoSignTransaction(){
    delete ui;
}

void CoSignTransaction::UpdateLabels() {
    ui->label_3->setText("Enter long code of transaction to be signed");
    if (pwalletMain) {
        if (pwalletMain->HasPendingTx()) {
            ui->label_3->setText("You have a pending transaction, please enter the synchronized key images \nfrom your co-signers here to co-sign the pending transaction.");
        }
    }
}

void CoSignTransaction::cosignTransaction()
{
    std::string hexPartial = ui->hexCode->toPlainText().trimmed().toStdString();
	if (!IsHex(hexPartial)) return;
    
    vector<unsigned char> partialTxData(ParseHex(hexPartial));
	CDataStream ssdata(partialTxData, SER_NETWORK, PROTOCOL_VERSION);
	CPartialTransaction partialTx;
	try {
		ssdata >> partialTx;
	} catch (const std::exception&) {
		return;
	}
    if (!pwalletMain->CoSignPartialTransaction(partialTx)) {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Transaction co-sining failed");
        msgBox.setText("Failed to cosign transaction.\n\n");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.exec();
		return;
    }

    CDataStream dex(SER_NETWORK, PROTOCOL_VERSION);
    dex << partialTx;
    std::string hex = HexStr(dex.begin(), dex.end());
    ui->signedHex->setReadOnly(true);
    ui->signedHex->setText(QString::fromStdString(hex));
    QMessageBox msgBox;
    msgBox.setWindowTitle("Transaction Signed");
    msgBox.setText("Multisignature transaction CoSigned by you. You can copy the hex code and send it to your co-signers to synchronize key image and finish the transaction.\n\n");
    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
    msgBox.setIcon(QMessageBox::Information);
    msgBox.exec();
}



