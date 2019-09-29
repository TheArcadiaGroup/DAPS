// Copyright (c) 2011-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The DAPScoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ui_keyimagesync.h"

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
#include "keyimagesync.h"


KeyImageSync::KeyImageSync(QWidget* parent) : QDialog(parent),
                                                    ui(new Ui::KeyImageSync),
                                                    clientModel(0),
                                                    // m_SizeGrip(this),
                                                    model(0)
{
    ui->setupUi(this);
    connect(ui->syncKeyImageButton, SIGNAL(clicked()), this, SLOT(generateKeyImageHex()));
}

void KeyImageSync::setClientModel(ClientModel* clientModel)
{
    this->clientModel = clientModel;

    if (clientModel) {
    }
}

void KeyImageSync::setModel(WalletModel* model)
{
    this->model = model;
    if (model && model->getOptionsModel()) {
        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this,
            SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));
    }
}

void KeyImageSync::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                              const CAmount& zerocoinBalance, const CAmount& unconfirmedZerocoinBalance, const CAmount& immatureZerocoinBalance,
                              const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    ui->labelBalance->setText(BitcoinUnits::floorHtmlWithUnit(0, balance, false, BitcoinUnits::separatorAlways));
}

KeyImageSync::~KeyImageSync(){
    delete ui;
}

void KeyImageSync::generateKeyImageHex()
{
	std::string hexCode = ui->hexCode->toPlainText().toStdString();
	if (!IsHex(hexCode)) return;
	vector<unsigned char> partialTxHex(ParseHex(hexCode));
	CDataStream ssdata(partialTxHex, SER_NETWORK, PROTOCOL_VERSION);
	CPartialTransaction ptx;
	try {
		ssdata >> ptx;
	} catch (const std::exception&) {
		return;
	}
	CListPKeyImageAlpha keyImageAlpha;
	model->getCWallet()->generatePKeyImageAlphaListFromPartialTx(ptx, keyImageAlpha);
	CDataStream ssWritedata(SER_NETWORK, PROTOCOL_VERSION);
	ssWritedata << keyImageAlpha;
	std::string hex = HexStr(ssWritedata.begin(), ssWritedata.end());
	ui->signedHex->setText(QString::fromStdString(hex));
	ui->signedHex->setReadOnly(true);
}



