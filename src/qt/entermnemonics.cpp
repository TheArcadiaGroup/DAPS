#include "entermnemonics.h"
#include "ui_entermnemonics.h"

#include "allocators.h"
#include "guiconstants.h"
#include "walletmodel.h"
#include "walletdb.h"

#include <QDateTime>
#include <QMessageBox>

EnterMnemonics::EnterMnemonics(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                                  ui(new Ui::EnterMnemonics)
{
    ui->setupUi(this);
    connect(ui->btnNext, SIGNAL(clicked()), this, SLOT(on_next()));
}

EnterMnemonics::~EnterMnemonics()
{
    delete ui;
}

void EnterMnemonics::on_next()
{
    std::string phrase = ui->mnemonics->toPlainText().toStdString();
    try {
        pwalletMain->GenerateNewHDChain(&phrase);
        QMessageBox::information(this, "Recovery Phrase Import Succeed", "Your mnemonics has been successfully imported into the wallet. Rescanning will be scheduled to recover all your funds.", QMessageBox::Ok);
        CBlockLocator loc = chainActive.GetLocator(chainActive[0]);
        pwalletMain->SetBestChain(loc);
        CWalletDB(pwalletMain->strWalletFile).WriteScannedBlockHeight(0); //reschedule to rescan entire chain to recover all funds and history        
        accept();
    } catch (std::exception& ex) {
       QMessageBox::warning(this, "Recovery phrase invalid", "Recovery phrase is invalid", QMessageBox::Ok);
    }
}