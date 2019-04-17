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
#include <QDoubleValidator>
#include <QFile>
#include <QTextStream>

using namespace std;

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
    //connect(ui->pushButtonSave, SIGNAL(clicked()), this, SLOT(on_pushButtonSave_clicked()));

    QDoubleValidator *dblVal = new QDoubleValidator(0, 2100000000, 6, ui->lineEditWithhold);
    dblVal->setNotation(QDoubleValidator::StandardNotation);
    dblVal->setLocale(QLocale::C);
    ui->lineEditWithhold->setValidator(dblVal);
    ui->lineEditWithhold->setPlaceholderText("DAPS Amount");
    if (nReserveBalance > 0)
        ui->lineEditWithhold->setText(BitcoinUnits::format(0, nReserveBalance).toUtf8());

    //connect(ui->pushButtonPassword, SIGNAL(clicked()), this, SLOT(on_pushButtonPassword_clicked()));
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

static inline int64_t roundint64(double d)
{
    return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
}

CAmount OptionsPage::getValidatedAmount() {
    double dAmount = ui->lineEditWithhold->text().toDouble();
    if (dAmount < 0.0 || dAmount > 2100000000.0)
        throw runtime_error("Invalid amount, amount should be < 2.1B DAPS");
    CAmount nAmount = roundint64(dAmount * COIN);
    return nAmount;
}

OptionsPage::~OptionsPage()
{
    delete ui;
}

void OptionsPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void OptionsPage::on_pushButtonSave_clicked() {
    if (ui->lineEditWithhold->text().trimmed().isEmpty()) {
        QMessageBox(QMessageBox::Information, tr("Information"), tr("DAPS reserve amount should be filled"), QMessageBox::Ok).exec();
        return;
    }
    nReserveBalance = getValidatedAmount();

    boost::filesystem::path reserveFilePath = GetDataDir() / "reserve.dat";
    QString filename= reserveFilePath.c_str();
    QFile file( filename );
    if ( file.open(QIODevice::ReadWrite) )
    {
        QTextStream stream( &file );
        stream << nReserveBalance / COIN << endl;
    }
    file.close();

    emit model->stakingStatusChanged(nLastCoinStakeSearchInterval);
    QMessageBox(QMessageBox::Information, tr("Information"), tr("Reserve balance " + BitcoinUnits::format(0, nReserveBalance).toUtf8() + " is successfully set!"), QMessageBox::Ok).exec();
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
    //disable password submit button
    QMessageBox(QMessageBox::Information, tr("Information"), tr("This feature is currently not available"), QMessageBox::Ok).exec();
    /*SecureString oldPass = SecureString();
    oldPass.reserve(MAX_PASSPHRASE_SIZE);
    oldPass.assign( ui->lineEditOldPass->text().toStdString().c_str() );
    SecureString newPass = SecureString();
    newPass.reserve(MAX_PASSPHRASE_SIZE);
    oldPass.assign( ui->lineEditNewPass->text().toStdString().c_str() );

    bool success = false;

    if ( (ui->lineEditNewPass->text() == ui->lineEditNewPassRepeat->text()) && (ui->lineEditNewPass->text().length()) && (ui->lineEditNewPass->text().contains(" ")) )
    {
        if (!matchNewPasswords()) auto errorBox = QMessageBox::warning(this, tr("Password Error"),tr("New passwords do not match."));
        if (!model->getEncryptionStatus()){
            model->setWalletEncrypted(true, newPass);
            success = true;
        } else {
            if (model->changePassphrase(oldPass,newPass)) {
                ui->lineEditOldPass->setStyleSheet(GUIUtil::loadStyleSheet());
                success = true;
                auto errorBox = QMessageBox::information(this, "", tr("Password changed"));
            } else {
                ui->lineEditOldPass->setStyleSheet("border-color:red");
                auto errorBox = QMessageBox::warning(this, tr("Password Error"),tr("Password rejected by wallet."));
            }
        }
        ui->lineEditOldPass->repaint();
    } else {
         success = false;
        validateNewPass();
        auto errorBox = QMessageBox::warning(this, tr("Password Error"),tr("Password rejected by wallet."));
    }

    if (success)
        ui->pushButtonPassword->setStyleSheet("border: 2px solid green");
    else ui->pushButtonPassword->setStyleSheet("border: 2px solid red");
    ui->pushButtonPassword->repaint();*/
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