#include "2fadialog.h"
#include "ui_2fadialog.h"
#include "receiverequestdialog.h"
#include "qgoogleauth.h"
#include "init.h"
#include <QDateTime>
#include <QDesktopServices>

TwoFADialog::TwoFADialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TwoFADialog)
{
    ui->setupUi(this);

    QIntValidator *intVal_1 = new QIntValidator(0, 9, ui->txtcode_1);
    intVal_1->setLocale(QLocale::C);
    ui->txtcode_1->setValidator(intVal_1);
    ui->txtcode_1->setAlignment(Qt::AlignCenter);

    QIntValidator *intVal_2 = new QIntValidator(0, 9, ui->txtcode_2);
    intVal_2->setLocale(QLocale::C);
    ui->txtcode_2->setValidator(intVal_2);
    ui->txtcode_2->setAlignment(Qt::AlignCenter);

    QIntValidator *intVal_3 = new QIntValidator(0, 9, ui->txtcode_3);
    intVal_3->setLocale(QLocale::C);
    ui->txtcode_3->setValidator(intVal_3);
    ui->txtcode_3->setAlignment(Qt::AlignCenter);

    QIntValidator *intVal_4 = new QIntValidator(0, 9, ui->txtcode_4);
    intVal_4->setLocale(QLocale::C);
    ui->txtcode_4->setValidator(intVal_4);
    ui->txtcode_4->setAlignment(Qt::AlignCenter);

    QIntValidator *intVal_5 = new QIntValidator(0, 9, ui->txtcode_5);
    intVal_5->setLocale(QLocale::C);
    ui->txtcode_5->setValidator(intVal_5);
    ui->txtcode_5->setAlignment(Qt::AlignCenter);

    QIntValidator *intVal_6 = new QIntValidator(0, 9, ui->txtcode_6);
    intVal_6->setLocale(QLocale::C);
    ui->txtcode_6->setValidator(intVal_6);
    ui->txtcode_6->setAlignment(Qt::AlignCenter);

    connect(ui->btnOK, SIGNAL(clicked()), this, SLOT(on_acceptCode()));
    connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(reject()));

    ui->lblOpenAppURL->setVisible(false);
    ui->lblOpenAppURL->setText("<a href=\"chrome://apps\">OPEN AUTHENTICATION APP</a>");
    ui->lblOpenAppURL->setTextFormat(Qt::RichText);
    // ui->lblOpenAppURL->setTextInteractionFlags(Qt::TextBrowserInteraction);
    // ui->lblOpenAppURL->setOpenExternalLinks(true);
    connect(ui->lblOpenAppURL, SIGNAL(linkActivated(const QString&)), SLOT(on_app_linkActivated(const QString&)));
}

TwoFADialog::~TwoFADialog()
{
    delete ui;
}

void TwoFADialog::on_acceptCode()
{
    QString code;
    char code1, code2, code3, code4, code5, code6;
    QString input;
    char* chrlist;
    QRegExp re("\\d*");  // a digit (\d), zero or more times (*)
    input = ui->txtcode_1->text();
    if (input.length() > 1)
        return;
    if (!re.exactMatch(input))
        return;
    chrlist = input.toUtf8().data();
    code1 = chrlist[0];

    input = ui->txtcode_2->text();
    if (input.length() > 1)
        return;
    if (!re.exactMatch(input))
        return;
    chrlist = input.toUtf8().data();
    code2 = chrlist[0];

    input = ui->txtcode_3->text();
    if (input.length() > 1)
        return;
    if (!re.exactMatch(input))
        return;
    chrlist = input.toUtf8().data();
    code3 = chrlist[0];

    input = ui->txtcode_4->text();
    if (input.length() > 1)
        return;
    if (!re.exactMatch(input))
        return;
    chrlist = input.toUtf8().data();
    code4 = chrlist[0];

    input = ui->txtcode_5->text();
    if (input.length() > 1)
        return;
    if (!re.exactMatch(input))
        return;
    chrlist = input.toUtf8().data();
    code5 = chrlist[0];

    input = ui->txtcode_6->text();
    if (input.length() > 1)
        return;
    if (!re.exactMatch(input))
        return;
    chrlist = input.toUtf8().data();
    code6 = chrlist[0];

    code.sprintf("%c%c%c%c%c%c", code1, code2, code3, code4, code5, code6);

    QString codeSetting = settings.value("2FACode").toString();
    if (codeSetting == "") {
        QString result = "";
        CWalletDB walletdb(pwalletMain->strWalletFile);
        CAccount account;
        walletdb.ReadAccount("", account);
        CBitcoinAddress address(account.vchPubKey.GetID());
        std::string addr = "";
        for (char c : address.ToString()) {
            if (!std::isdigit(c)) addr += c;
        }
                    
        QString data;
        data.sprintf("%s", addr.c_str());
        result = QGoogleAuth::generatePin(data.toUtf8());
        
        if (result != code)
            return;

        settings.setValue("2FACode", code);
    }

    accept();
}

void TwoFADialog::on_app_linkActivated(const QString &link) {
    QDesktopServices::openUrl(QUrl(link));
}