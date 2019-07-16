#include "encryptdialog.h"
#include "ui_encryptdialog.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"

#include <QMessageBox>
#include <QCloseEvent>

EncryptDialog::EncryptDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EncryptDialog)
{
    ui->setupUi(this);

    connect(ui->linePwd, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPass()));
    connect(ui->linePwdConfirm, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPassRepeat()));
    connect(ui->btnOK, SIGNAL(clicked()), this, SLOT(on_acceptPassphrase()));
    connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(on_btnCancel()));
}

EncryptDialog::~EncryptDialog()
{
    delete ui;
}

void EncryptDialog::setModel(WalletModel* model)
{
    this->model = model;
}

void EncryptDialog::closeEvent (QCloseEvent *event)
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, "Wallet encryption required", "There was no passphrase entered for the wallet. Wallet encryption is required for the security of your funds. What would you like to do?", QMessageBox::Retry|QMessageBox::Close);
      if (reply == QMessageBox::Retry) {
      event->ignore();
      } else {
      QApplication::quit();
      }
}

void EncryptDialog::on_btnCancel()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, "Wallet encryption required", "There was no passphrase entered for the wallet. Wallet encryption is required for the security of your funds. What would you like to do?", QMessageBox::Retry|QMessageBox::Close);
      if (reply == QMessageBox::Retry) {
      return;
      } else {
      QApplication::quit();
      }
}

void EncryptDialog::on_acceptPassphrase() {
    SecureString newPass = SecureString();
    newPass.reserve(MAX_PASSPHRASE_SIZE);
    newPass.assign( ui->linePwd->text().toStdString().c_str() );

    SecureString newPass2 = SecureString();
    newPass2.reserve(MAX_PASSPHRASE_SIZE);
    newPass2.assign(ui->linePwdConfirm->text().toStdString().c_str() );

    if ( (!ui->linePwd->text().length()) ) {
        QMessageBox::critical(this, tr("Wallet encryption failed"),
                    tr("The passphrase entered for wallet encryption was empty. Please try again."));
        return;
    }
    
    if (newPass == newPass2) {
        if (model->setWalletEncrypted(true, newPass))
            QMessageBox::information(this, tr("Wallet encryption successful"),
                    tr("Wallet passphrase was successfully set. Please remember your passphrase as there is no way to recover it."));
        accept();
    } else {
            QMessageBox::critical(this, tr("Wallet encryption failed"),
                    tr("The passphrases entered for wallet encryption do not match. Please try again."));
        return;
    }
}

void EncryptDialog::validateNewPass()
{
    if ( (!ui->linePwd->text().length()) )
        ui->linePwd->setStyleSheet("border-color: red");
    else ui->linePwd->setStyleSheet(GUIUtil::loadStyleSheet());
    matchNewPasswords();
    ui->linePwd->repaint();
}

void EncryptDialog::validateNewPassRepeat()
{
    matchNewPasswords();
}

bool EncryptDialog::matchNewPasswords()
{
    if (ui->linePwd->text()==ui->linePwdConfirm->text())
    {
        ui->linePwdConfirm->setStyleSheet(GUIUtil::loadStyleSheet());
        ui->linePwdConfirm->repaint();
        return true;
    } else
    {
        ui->linePwdConfirm->setStyleSheet("border-color: red");
        ui->linePwdConfirm->repaint();
        return false;
    }
}