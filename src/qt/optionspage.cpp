// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "optionspage.h"
#include "ui_optionspage.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"
#include "optionsmodel.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QDataWidgetMapper>

OptionsPage::OptionsPage(QWidget* parent) : QDialog(parent),
                                                          ui(new Ui::OptionsPage),
                                                          model(0),
                                                          mapper(0)
{
    ui->setupUi(this);

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);

    ui->toggleTheme->setState(settings.value("theme")!="light");
    connect(ui->toggleTheme, SIGNAL(stateChanged(ToggleButton*)), this, SLOT(changeTheme(ToggleButton*)));

    connect(ui->lineEditNewPass, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPass()));
    connect(ui->lineEditNewPassRepeat, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPassRepeat()));
    connect(ui->lineEditOldPass, SIGNAL(textChanged(const QString &)), this, SLOT(onOldPassChanged()));
}

void OptionsPage::setModel(WalletModel* model)
{
    this->model = model;
    this->options = model->getOptionsModel();

    if (model && model->getOptionsModel()) {
        model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
    }

    mapper->setModel(options);
    setMapper();
    mapper->toFirst();
}

OptionsPage::~OptionsPage()
{
    delete ui;
}

void OptionsPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}


void OptionsPage::keyPressEvent(QKeyEvent* event)
{

    this->QDialog::keyPressEvent(event);
}

void OptionsPage::setMapper()
{
    //mapper->addMapping([component], OptionsModel::[setting]);
}

void OptionsPage::on_pushButtonPassword_clicked()
{
    SecureString oldPass = SecureString();
    oldPass.reserve(MAX_PASSPHRASE_SIZE);
    oldPass.assign( ui->lineEditOldPass->text().toStdString().c_str() );
    SecureString newPass = SecureString();
    newPass.reserve(MAX_PASSPHRASE_SIZE);
    oldPass.assign( ui->lineEditNewPass->text().toStdString().c_str() );

    bool success = false;

    if ( (ui->lineEditNewPass->text() == ui->lineEditNewPassRepeat->text()) && (ui->lineEditNewPass->text().length()) && (ui->lineEditNewPass->text().contains(" ")) )
    {
        if (!model->getEncryptionStatus()){
            model->setWalletEncrypted(true, newPass);
            success = true;
        } else {
            if (model->changePassphrase(oldPass,newPass)) {
                ui->lineEditOldPass->setStyleSheet(GUIUtil::loadStyleSheet());
                success = true;
            } else {
                ui->lineEditOldPass->setStyleSheet("border-color:red");
            }
        }
        ui->lineEditOldPass->repaint();
    } else {
        success = false;
        validateNewPass();
    }

    if (success)
        ui->pushButtonPassword->setStyleSheet("border: 2px solid green");
    else ui->pushButtonPassword->setStyleSheet("border: 2px solid red");
    ui->pushButtonPassword->repaint();
}

void OptionsPage::on_pushButtonBackup_clicked(){
    if (model->backupWallet(QString("BackupWallet.dat")))
        ui->pushButtonBackup->setStyleSheet("border: 2px solid green");
    else ui->pushButtonBackup->setStyleSheet("border: 2px solid red");
    ui->pushButtonBackup->repaint();
}

void OptionsPage::validateNewPass()
{
    if ( (ui->lineEditNewPass->text().contains(" ")) || (!ui->lineEditNewPass->text().length()) )
        ui->lineEditNewPass->setStyleSheet("border-color: red");
    else ui->lineEditNewPass->setStyleSheet(GUIUtil::loadStyleSheet());
    matchNewPasswords();
    ui->lineEditNewPass->repaint();
}

void OptionsPage::validateNewPassRepeat()
{
    matchNewPasswords();
}

void OptionsPage::onOldPassChanged()
{
    QString stylesheet = GUIUtil::loadStyleSheet();
    ui->lineEditOldPass->setStyleSheet(stylesheet);
    ui->lineEditOldPass->repaint();
    ui->pushButtonPassword->setStyleSheet(stylesheet);
    ui->pushButtonPassword->repaint();
    if (!ui->lineEditNewPass->text().length())
        ui->lineEditNewPass->setStyleSheet("border-color: red");
        ui->lineEditNewPass->repaint();
}

bool OptionsPage::matchNewPasswords()
{
    if (ui->lineEditNewPass->text()==ui->lineEditNewPassRepeat->text())
    {
        ui->lineEditNewPassRepeat->setStyleSheet(GUIUtil::loadStyleSheet());
        ui->lineEditNewPassRepeat->repaint();
        return true;
    } else
    {
        ui->lineEditNewPassRepeat->setStyleSheet("border-color: red");
        ui->lineEditNewPassRepeat->repaint();
        return false;
    }
}

void OptionsPage::changeTheme(ToggleButton* widget)
{
    if (widget->getState())
        settings.setValue("theme", "dark");
    else settings.setValue("theme", "light");
    GUIUtil::refreshStyleSheet();
}