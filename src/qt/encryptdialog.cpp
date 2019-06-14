#include "encryptdialog.h"
#include "ui_encryptdialog.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"

#include <QMessageBox>

EncryptDialog::EncryptDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EncryptDialog)
{
    ui->setupUi(this);

    connect(ui->linePwd, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPass()));
    connect(ui->linePwdConfirm, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPassRepeat()));
    connect(ui->btnOK, SIGNAL(clicked()), this, SLOT(on_acceptPassphrase()));
    connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(reject()));
}

EncryptDialog::~EncryptDialog()
{
    delete ui;
}

void EncryptDialog::setModel(WalletModel* model)
{
    this->model = model;
}

void EncryptDialog::on_acceptPassphrase() {
    SecureString newPass = SecureString();
    newPass.reserve(MAX_PASSPHRASE_SIZE);
    newPass.assign( ui->linePwd->text().toStdString().c_str() );

    SecureString newPass2 = SecureString();
    newPass2.reserve(MAX_PASSPHRASE_SIZE);
    newPass2.assign(ui->linePwdConfirm->text().toStdString().c_str() );

    if ( (ui->linePwd->text().contains(" ")) || (!ui->linePwd->text().length()) )
        return;
    
    if (newPass == newPass2) {
        if (model->setWalletEncrypted(true, newPass)) {
            QMessageBox::information(this, tr("Wallet encrypted"),
                    tr("Wallet passphrase was successfully changed."));
        } else {
            QMessageBox::critical(this, tr("Wallet encryption failed"),
                    tr("The passphrase entered for the wallet decryption was incorrect."));
        }

        accept();
    }
}

void EncryptDialog::validateNewPass()
{
    if ( (ui->linePwd->text().contains(" ")) || (!ui->linePwd->text().length()) )
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