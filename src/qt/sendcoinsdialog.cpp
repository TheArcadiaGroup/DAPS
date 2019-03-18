// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The DAPScoin developers
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

#include <regex>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>


SendCoinsDialog::SendCoinsDialog(QWidget* parent) : QDialog(parent),
                                                    ui(new Ui::SendCoinsDialog),
                                                    clientModel(0),
                                                    model(0),
                                                    fNewRecipientAllowed(true)
{
    ui->setupUi(this);

    addEntry();

    connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));

    QSettings settings;
      if (!settings.contains("nRingSize"))
        settings.setValue("nRingSize", 6);

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

        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this,
            SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));

        updateRingSize();
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
    bool isValidAmount = ((recipient.amount>0) && (recipient.amount<=model->getBalance()));

    form->errorAddress(isValidAddresss);
    form->errorAmount(isValidAmount);

    if (!isValidAddresss||!isValidAmount)
        return;

    CWalletTx resultTx; 
    CAmount* amount = new CAmount();
    BitcoinUnits::parse(0, QString::number(recipient.amount), amount);
    bool success=NULL;
    try {
        success = pwalletMain->SendToStealthAddress(
            recipient.address.toStdString(),
            *amount,
            resultTx,
            false
        );
    } catch (const std::exception& err) {
        auto errorbox = QMessageBox::warning(this, "Could not send", QString(err.what()));
        return;
    }

    if (success){
        QMessageBox txcomplete;
        txcomplete.setText("Transaction initialized.");
        txcomplete.setInformativeText(resultTx.GetHash().GetHex().c_str());
        txcomplete.setStyleSheet(GUIUtil::loadStyleSheet());
        txcomplete.setStyleSheet("QMessageBox {messagebox-text-interaction-flags: 5;}");
        txcomplete.exec();
    }
}

SendCoinsEntry* SendCoinsDialog::addEntry()
{
    SendCoinsEntry* entry = new SendCoinsEntry(this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(SendCoinsEntry*)), this, SLOT(removeEntry(SendCoinsEntry*)));
    connect(entry, SIGNAL(payAmountChanged()), this, SLOT(coinControlUpdateLabels()));

    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if (bar)
        bar->setSliderPosition(bar->maximum());
    return entry;
}

void SendCoinsDialog::updateRingSize()
{
    QSettings settings;
    // settings.setValue("nRingSize", ui->horizontalSliderRingSize->value());
    // ui->labelRingSizeValue->setText(settings.value("nRingSize").toString());
}



