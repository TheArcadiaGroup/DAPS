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
#include "2faqrdialog.h"
#include "2fadialog.h"
#include "2faconfirmdialog.h"
#include "zxcvbn.h"

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
                                                          // m_SizeGrip(this),
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

    QDoubleValidator *dblVal = new QDoubleValidator(0, Params().MAX_MONEY, 6, ui->lineEditWithhold);
    dblVal->setNotation(QDoubleValidator::StandardNotation);
    dblVal->setLocale(QLocale::C);
    ui->lineEditWithhold->setValidator(dblVal);
    ui->lineEditWithhold->setPlaceholderText("DAPS Amount");
    if (nReserveBalance > 0)
        ui->lineEditWithhold->setText(BitcoinUnits::format(0, nReserveBalance).toUtf8());

    bool stkStatus = pwalletMain->ReadStakingStatus();
    ui->toggleStaking->setState(nLastCoinStakeSearchInterval | stkStatus);
    connect(ui->toggleStaking, SIGNAL(stateChanged(ToggleButton*)), this, SLOT(on_EnableStaking(ToggleButton*)));

    connect(ui->pushButtonRecovery, SIGNAL(clicked()), this, SLOT(onShowMnemonic()));

    bool twoFAStatus = settings.value("2FA")=="enabled";
    if (twoFAStatus)
        enable2FA();
    else
        disable2FA();

    ui->toggle2FA->setState(twoFAStatus);
    connect(ui->toggle2FA, SIGNAL(stateChanged(ToggleButton*)), this, SLOT(on_Enable2FA(ToggleButton*)));

    connect(ui->btn_day, SIGNAL(clicked()), this, SLOT(on_day()));
    connect(ui->btn_week, SIGNAL(clicked()), this, SLOT(on_week()));
    connect(ui->btn_month, SIGNAL(clicked()), this, SLOT(on_month()));

    ui->lblAuthCode->setVisible(false);
    ui->code_1->setVisible(false);
    ui->code_2->setVisible(false);
    ui->code_3->setVisible(false);
    ui->code_4->setVisible(false);
    ui->code_5->setVisible(false);
    ui->code_6->setVisible(false);

    timerStakingToggleSync = new QTimer();
    connect(timerStakingToggleSync, SIGNAL(timeout()), this, SLOT(setStakingToggle()));
    timerStakingToggleSync->start(10000);
}

void OptionsPage::setStakingToggle()
{
	ui->toggleStaking->setState(fGenerateDapscoins);
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
    if (dAmount < 0.0 || dAmount > Params().MAX_MONEY)
        throw runtime_error("Invalid amount, amount should be < 2.1B DAPS");
    CAmount nAmount = roundint64(dAmount * COIN);
    return nAmount;
}

OptionsPage::~OptionsPage()
{
	delete timerStakingToggleSync;
    delete ui;
}

void OptionsPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void OptionsPage::on_pushButtonSave_clicked() {
    if (ui->lineEditWithhold->text().trimmed().isEmpty()) {
        ui->lineEditWithhold->setStyleSheet("border: 2px solid red");
        QMessageBox msgBox;
        msgBox.setWindowTitle("Reserve Balance Empty");
        msgBox.setText("DAPS reserve amount is empty and must be a minimum of 1.\nPlease click Disable if you would like to turn it off.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Information);
        msgBox.exec();
        return;
    }
    nReserveBalance = getValidatedAmount();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    walletdb.WriteReserveAmount(nReserveBalance / COIN);

    emit model->stakingStatusChanged(nLastCoinStakeSearchInterval);
    ui->lineEditWithhold->setStyleSheet(GUIUtil::loadStyleSheet());
    QMessageBox msgBox;
    msgBox.setWindowTitle("Reserve Balance Set");
    msgBox.setText("Reserve balance of " + BitcoinUnits::format(0, nReserveBalance).toUtf8() + " is successfully set.");
    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
    msgBox.setIcon(QMessageBox::Information);
    msgBox.exec();
}

void OptionsPage::on_pushButtonDisable_clicked() {
    ui->lineEditWithhold->setText("0");
    nReserveBalance = getValidatedAmount();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    walletdb.WriteReserveAmount(nReserveBalance / COIN);

    emit model->stakingStatusChanged(nLastCoinStakeSearchInterval);
    QMessageBox msgBox;
    msgBox.setWindowTitle("Reserve Balance Disabled");
    msgBox.setText("Reserve balance disabled.");
    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
    msgBox.setIcon(QMessageBox::Information);
    msgBox.exec();
}

void OptionsPage::keyPressEvent(QKeyEvent* event)
{

    this->QDialog::keyPressEvent(event);
}

void OptionsPage::setMapper()
{
}

void OptionsPage::on_pushButtonPassword_clicked()
{
    if ( (!ui->lineEditNewPass->text().length()) || (!ui->lineEditNewPassRepeat->text().length()) ) {
        QMessageBox::critical(this, tr("Wallet Encryption Failed"),
                    tr("The passphrase entered for wallet encryption was empty or contained spaces. Please try again."));
        return;
    }
    //disable password submit button
    SecureString oldPass = SecureString();
    oldPass.reserve(MAX_PASSPHRASE_SIZE);
    oldPass.assign( ui->lineEditOldPass->text().toStdString().c_str() );
    SecureString newPass = SecureString();
    newPass.reserve(MAX_PASSPHRASE_SIZE);
    newPass.assign( ui->lineEditNewPass->text().toStdString().c_str() );

    SecureString newPass2 = SecureString();
    newPass2.reserve(MAX_PASSPHRASE_SIZE);
    newPass2.assign(ui->lineEditNewPassRepeat->text().toStdString().c_str() );

    bool success = false;

    if (newPass == newPass2) {
        double guesses;

        if (oldPass == newPass) {
            QMessageBox::critical(this, tr("Wallet Encryption Failed"),
                    tr("The passphrases entered for wallet encryption is older. Please try again."));
        }
        else if (newPass.length() < 10) {
            QMessageBox::critical(this, tr("Wallet Encryption Failed"),
                    tr("The passphrase's length has to be more than 10. Please try again."));
        }
        else if (!pwalletMain->checkPassPhraseRule(newPass.c_str())) {
            QMessageBox::critical(this, tr("Wallet Encryption Failed"),
                    tr("The passphrase must contain lower, upper, digit, symbol. Please try again."));
        }
        else if (zxcvbn_password_strength(newPass.c_str(), NULL, &guesses, NULL) < 0 || guesses < 10000) {
            QMessageBox::critical(this, tr("Wallet Encryption Failed"),
                    tr("The passphrase is too weak. You must use a minimum passphrase length of 10 characters and use uppercase letters, lowercase letters, numbers, and symbols. Please try again."));
        }
    	else if (model->changePassphrase(oldPass, newPass)) {
    		QMessageBox::information(this, tr("Passphrase Change Successful"),
                    tr("Wallet passphrase was successfully changed. Please remember your passphrase as there is no way to recover it."));
    		success = true;
        }
    } else {
    		QMessageBox::critical(this, tr("Wallet Encryption Failed"),
    				tr("The passphrases entered for wallet encryption do not match. Please try again."));
    }

    if (success)
        ui->pushButtonPassword->setStyleSheet("border: 2px solid green");
    else ui->pushButtonPassword->setStyleSheet("border: 2px solid red");
    ui->pushButtonPassword->repaint();
}

void OptionsPage::on_pushButtonPasswordClear_clicked()
{
    ui->lineEditOldPass->clear();
    ui->lineEditNewPass->clear();
    ui->lineEditNewPassRepeat->clear();
    ui->lineEditOldPass->setStyleSheet(GUIUtil::loadStyleSheet());
    ui->lineEditNewPass->setStyleSheet(GUIUtil::loadStyleSheet());
    ui->lineEditNewPassRepeat->setStyleSheet(GUIUtil::loadStyleSheet());
}

void OptionsPage::on_pushButtonBackup_clicked(){
    if (model->backupWallet(QString("BackupWallet.dat"))) {
        ui->pushButtonBackup->setStyleSheet("border: 2px solid green");
        QMessageBox msgBox;
        msgBox.setWindowTitle("Wallet Backup Successful");
        msgBox.setText("Wallet has been successfully backed up to BackupWallet.dat in the current directory.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Information);
        msgBox.exec();
    } else { ui->pushButtonBackup->setStyleSheet("border: 2px solid red");
        QMessageBox msgBox;
        msgBox.setWindowTitle("Wallet Backup Failed");
        msgBox.setText("Wallet backup failed. Please try again.");
        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.exec();
}
    ui->pushButtonBackup->repaint();
}

void OptionsPage::validateNewPass()
{
    if (!ui->lineEditNewPass->text().length())
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

void OptionsPage::on_EnableStaking(ToggleButton* widget)
{
    if (chainActive.Height() < Params().LAST_POW_BLOCK()) {
    	if (widget->getState()) {
            QString msg("PoW blocks are still being mined.\nPlease wait until Block #" + Params().LAST_POW_BLOCK());
            QMessageBox msgBox;
            msgBox.setWindowTitle("Information");
            msgBox.setIcon(QMessageBox::Information);
            msgBox.setText(msg);
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.exec();
    	}
    	widget->setState(false);
    	pwalletMain->WriteStakingStatus(false);
    	pwalletMain->walletStakingInProgress = false;
        return;
    }
	if (widget->getState()){
        QString error;
        StakingStatusError stt = model->getStakingStatusError(error);
        if (!error.length()) {
            pwalletMain->WriteStakingStatus(true);
            emit model->stakingStatusChanged(true);
            model->generateCoins(true, 1);
        } else {
        	if (stt != StakingStatusError::UTXO_UNDER_THRESHOLD) {
        		QMessageBox msgBox;
        		QString msg(error);
        		msgBox.setWindowTitle("Warning: Staking Issue");
        		msgBox.setIcon(QMessageBox::Warning);
        		msgBox.setText(msg);
        		msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
        		msgBox.exec();
        		widget->setState(false);
        		nLastCoinStakeSearchInterval = 0;
        		emit model->stakingStatusChanged(false);
        		pwalletMain->WriteStakingStatus(false);
        	} else {
        		QMessageBox::StandardButton reply;
        		reply = QMessageBox::question(this, "Create Stakable Transaction?", error, QMessageBox::Yes|QMessageBox::No);
        		if (reply == QMessageBox::Yes) {
        			//ask yes or no
        			//send to this self wallet MIN staking amount
        			std::string masterAddr;
        			model->getCWallet()->ComputeStealthPublicAddress("masteraccount", masterAddr);
        			CWalletTx resultTx;
        			bool success = false;
        			try {
        				success = model->getCWallet()->SendToStealthAddress(
        						masterAddr,
								CWallet::MINIMUM_STAKE_AMOUNT,
								resultTx,
								false
        				);
        			} catch (const std::exception& err) {
        				QMessageBox::warning(this, "Could not send", QString(err.what()));
        				return;
        			}

        			if (success){
        				QMessageBox txcomplete;
        				txcomplete.setText("Transaction initialized.");
        				txcomplete.setInformativeText(resultTx.GetHash().GetHex().c_str());
        				txcomplete.setStyleSheet(GUIUtil::loadStyleSheet());
        				txcomplete.setStyleSheet("QMessageBox {messagebox-text-interaction-flags: 5;}");
        				txcomplete.exec();
        				WalletUtil::getTx(pwalletMain, resultTx.GetHash());
        			}
        		} else {
        			widget->setState(false);
        			nLastCoinStakeSearchInterval = 0;
        			emit model->stakingStatusChanged(false);
        			pwalletMain->WriteStakingStatus(false);
        		}
        	}
        }
    } else {
        nLastCoinStakeSearchInterval = 0;
        model->generateCoins(false, 0);
        emit model->stakingStatusChanged(false);
        pwalletMain->walletStakingInProgress = false;
        pwalletMain->WriteStakingStatus(false);
    }
}

void OptionsPage::on_Enable2FA(ToggleButton* widget)
{
    if (widget->getState()) {
        TwoFAQRDialog qrdlg;
        qrdlg.setWindowTitle("2FA QRCode");
        qrdlg.setModel(this->model);
        qrdlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&qrdlg, SIGNAL(finished (int)), this, SLOT(qrDialogIsFinished(int)));
        qrdlg.exec();
    } else {
        typeOf2FA = DISABLE;

        TwoFAConfirmDialog codedlg;
        codedlg.setWindowTitle("2FACode Verification");
        codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
        codedlg.exec();
    }
}

void OptionsPage::qrDialogIsFinished(int result) {
    if(result == QDialog::Accepted){
        TwoFADialog codedlg;
        codedlg.setWindowTitle("2FACode Verification");
        codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&codedlg, SIGNAL(finished (int)), this, SLOT(dialogIsFinished(int)));
        codedlg.exec();
    }

    if (result == QDialog::Rejected)
        ui->toggle2FA->setState(false);

}

void OptionsPage::dialogIsFinished(int result) {
   if(result == QDialog::Accepted){
        settings.setValue("2FA", "enabled");
        QDateTime current = QDateTime::currentDateTime();
        settings.setValue("2FALastTime", current.toTime_t());
        enable2FA();

        QMessageBox::information(this, tr("SUCCESS!"),
        tr("Two-factor authentication has been successfully enabled."));
   }

   if (result == QDialog::Rejected)
        ui->toggle2FA->setState(false);
}

void OptionsPage::changeTheme(ToggleButton* widget)
{
    if (widget->getState())
        settings.setValue("theme", "dark");
    else settings.setValue("theme", "light");
    	GUIUtil::refreshStyleSheet();
}

void OptionsPage::disable2FA() {
    ui->code_1->setText("");
    ui->code_2->setText("");
    ui->code_3->setText("");
    ui->code_4->setText("");
    ui->code_5->setText("");
    ui->code_6->setText("");

    ui->label_3->setEnabled(false);
    ui->lblAuthCode->setEnabled(false);
    ui->label->setEnabled(false);
    ui->btn_day->setEnabled(false);
    ui->btn_week->setEnabled(false);
    ui->btn_month->setEnabled(false);

    ui->btn_day->setStyleSheet("border-color: none;");
    ui->btn_week->setStyleSheet("border-color: none;");
    ui->btn_month->setStyleSheet("border-color: none;");
    typeOf2FA = NONE2FA;
}

void OptionsPage::enable2FA() {
    ui->label_3->setEnabled(true);
    ui->lblAuthCode->setEnabled(true);
    ui->label->setEnabled(true);
    ui->btn_day->setEnabled(true);
    ui->btn_week->setEnabled(true);
    ui->btn_month->setEnabled(true);

    QString code = settings.value("2FACode").toString();
    if (code != "") {
        char chrlist[6];
        memcpy(chrlist, code.toUtf8().data(), 6);
        QString value;
        value.sprintf("%c", chrlist[0]);
        ui->code_1->setText(value);
        value.sprintf("%c", chrlist[1]);
        ui->code_2->setText(value);
        value.sprintf("%c", chrlist[2]);
        ui->code_3->setText(value);
        value.sprintf("%c", chrlist[3]);
        ui->code_4->setText(value);
        value.sprintf("%c", chrlist[4]);
        ui->code_5->setText(value);
        value.sprintf("%c", chrlist[5]);
        ui->code_6->setText(value);
    }
     
    int period = settings.value("2FAPeriod").toInt();
    typeOf2FA = NONE2FA;
    if (period == 1) {
        ui->btn_day->setStyleSheet("border-color: green;");
        typeOf2FA = DAY;
    }
    else if (period == 7) {
        ui->btn_week->setStyleSheet("border-color: green;");
        typeOf2FA = WEEK;
    }
    else if (period == 30) {
        ui->btn_month->setStyleSheet("border-color: green;");
        typeOf2FA = MONTH;
    }
}

void OptionsPage::confirmDialogIsFinished(int result) {
    if(result == QDialog::Accepted){
        if (typeOf2FA == DAY) {
            settings.setValue("2FAPeriod", "1");
            ui->btn_day->setStyleSheet("border-color: green;");
            ui->btn_week->setStyleSheet("border-color: white;");
            ui->btn_month->setStyleSheet("border-color: white;");
        } else if (typeOf2FA == WEEK) {
            settings.setValue("2FAPeriod", "7");
            ui->btn_day->setStyleSheet("border-color: white;");
            ui->btn_week->setStyleSheet("border-color: green;");
            ui->btn_month->setStyleSheet("border-color: white;");
        } else if (typeOf2FA == MONTH) {
            settings.setValue("2FAPeriod", "30");
            ui->btn_day->setStyleSheet("border-color: white;");
            ui->btn_week->setStyleSheet("border-color: white;");
            ui->btn_month->setStyleSheet("border-color: green;");
        } else if (typeOf2FA == DISABLE) {
            settings.setValue("2FA", "disabled");
            settings.setValue("2FACode", "");
            settings.setValue("2FAPeriod", 0);
            settings.setValue("2FALastTime", 0);
            disable2FA();
        }
    }

    if (result == QDialog::Rejected)
        ui->toggle2FA->setState(true);
}

void OptionsPage::on_day() {
    typeOf2FA = DAY;

    TwoFAConfirmDialog codedlg;
    codedlg.setWindowTitle("2FACode Verification");
    codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
    connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
    codedlg.exec();
}

void OptionsPage::on_week() {
    typeOf2FA = WEEK;

    TwoFAConfirmDialog codedlg;
    codedlg.setWindowTitle("2FACode Verification");
    codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
    connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
    codedlg.exec();   
}

void OptionsPage::on_month() {
    typeOf2FA = MONTH;

    TwoFAConfirmDialog codedlg;
    codedlg.setWindowTitle("2FACode Verification");
    codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
    connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
    codedlg.exec();
}

void OptionsPage::onShowMnemonic() {
    CHDChain hdChainCurrent;
    if (!pwalletMain->GetDecryptedHDChain(hdChainCurrent))
        return;

    SecureString mnemonic;
    SecureString mnemonicPass;
    if (!hdChainCurrent.GetMnemonic(mnemonic, mnemonicPass))
        return;

    QString mPhrase = std::string(mnemonic.begin(), mnemonic.end()).c_str();
    QMessageBox msgBox;
    msgBox.setWindowTitle("Mnemonic Recovery Phrase");
    msgBox.setText("Below is your Mnemonic Recovery Phrase, consisting of 24 seed words. Please copy/write these words down in order. We strongly recommend keeping multiple copies in different locations.");
    msgBox.setInformativeText("\n<b>" + mPhrase + "</b>");
    msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
    msgBox.exec();
}
