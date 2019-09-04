#include "multisigsetupfinish.h"
#include "ui_multisigsetupfinish.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"

#include <QMessageBox>
#include <QCloseEvent>

MultiSigSetupFinish::MultiSigSetupFinish(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MultiSigSetupFinish)
{
    ui->setupUi(this);

    connect(ui->btnDone, SIGNAL(clicked()), this, SLOT(on_btnDone()));
}

MultiSigSetupFinish::~MultiSigSetupFinish()
{
    delete ui;
}

void MultiSigSetupFinish::setModel(WalletModel* model)
{
    this->model = model;
    if (pwalletMain) {
    	std::string multisigAddress = pwalletMain->MyMultisigPubAddress();
    	pwalletMain->screenIndex++;
    	ui->textComboKey->setText(QString::fromStdString(multisigAddress));
    	ui->textComboKey->setReadOnly(true);
    }
}

void MultiSigSetupFinish::closeEvent (QCloseEvent *event)
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, "Multisig wallet setup required", "You need to configure multisig wallet to use?", QMessageBox::Retry|QMessageBox::Close);
      if (reply == QMessageBox::Retry) {
      event->ignore();
      } else {
      QApplication::quit();
      }
}

void MultiSigSetupFinish::on_btnDone()
{
	accept();
	pwalletMain->isMultisigSetupFinished = true;
}