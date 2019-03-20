// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "historypage.h"
#include "ui_historypage.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoingui.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "transactionrecord.h"
#include "walletmodel.h"

#include <QAction>
#include <QBrush>
#include <QCalendarWidget>
#include <QCursor>
#include <QItemSelection>
#include <QScrollBar>
#include <QSortFilterProxyModel>
#include <QTextDocument>
#include <QTime>
#include <QTextStream>
#include <QProcess>


HistoryPage::HistoryPage(QWidget* parent) : QDialog(parent),
                                            ui(new Ui::HistoryPage),
                                            model(0)

{
    ui->setupUi(this);

    initWidgets();
    connectWidgets();
    updateTableData(pwalletMain);
    updateAddressBookData(pwalletMain);
}


HistoryPage::~HistoryPage()
{
    delete ui;
}
void HistoryPage::initWidgets()
{
    //set String for all addresses
    allAddressString = "All addresses...";
    //adjust qt paint flags
    ui->tableView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tableView->setAttribute(Qt::WA_TranslucentBackground, true);
    //set date formats and init date from current timestamp
    ui->dateTimeEditTo->setDisplayFormat("M/d/yy");
    ui->dateTimeEditFrom->setDisplayFormat("M/d/yy");
    ui->dateTimeEditTo->setDateTime(QDateTime::currentDateTime().addDays(1));
    ui->dateTimeEditFrom->setDateTime(QDateTime::currentDateTime().addDays(-7));
    //add QTimeEdit's to QCalendar popups
    timeEditTo = new QTimeEdit(ui->dateTimeEditTo);
    timeEditFrom = new QTimeEdit(ui->dateTimeEditFrom);
    ui->dateTimeEditTo->calendarWidget()->parentWidget()->layout()->addWidget(timeEditTo);
    ui->dateTimeEditFrom->calendarWidget()->parentWidget()->layout()->addWidget(timeEditFrom);
    //remove window frames from widgets
    GUIUtil::setWindowless(ui->dateTimeEditTo->calendarWidget()->parentWidget());
    GUIUtil::setWindowless(ui->dateTimeEditFrom->calendarWidget()->parentWidget());
    GUIUtil::setWindowless(ui->comboBoxType->view()->parentWidget());
    GUIUtil::setWindowless(ui->lineEditDesc->view()->parentWidget());
    //color calendarwidgets
    GUIUtil::colorCalendarWidgetWeekends(ui->dateTimeEditTo->calendarWidget(), QColor("gray"));
    GUIUtil::colorCalendarWidgetWeekends(ui->dateTimeEditFrom->calendarWidget(), QColor("gray"));
    ui->horizontalLayout_2->setAlignment(Qt::AlignTop);
}

void HistoryPage::connectWidgets() //add functions to widget signals
{
    connect(ui->dateTimeEditTo, SIGNAL(dateChanged(const QDate&)), this, SLOT(updateFilter()));
    connect(ui->dateTimeEditFrom, SIGNAL(dateChanged(const QDate&)), this, SLOT(updateFilter()));
    connect(ui->comboBoxType, SIGNAL(currentIndexChanged(const int&)), this, SLOT(updateFilter()));
    //
    connect(ui->lineEditDesc, SIGNAL(currentIndexChanged(const int&)), this, SLOT(updateFilter()));
    connect(ui->lineEditDesc->lineEdit(), SIGNAL(textChanged(const QString&)), this, SLOT(updateFilter()));

    //
    connect(ui->lineEditAmount, SIGNAL(textChanged(const QString&)), this, SLOT(updateFilter()));
    //
    connect(timeEditFrom, SIGNAL(timeChanged(const QTime&)), this, SLOT(updateFilter()));
    connect(timeEditTo, SIGNAL(timeChanged(const QTime&)), this, SLOT(updateFilter()));
}

void HistoryPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    ui->tableView->setColumnWidth(2, this->width() * .65);
    ui->tableView->resizeColumnToContents(QHeaderView::ResizeToContents);
    ui->tableView->resizeColumnsToContents();
}


void HistoryPage::keyPressEvent(QKeyEvent* event)
{
    this->QDialog::keyPressEvent(event);
}

void HistoryPage::addTableData(std::map<QString, QString>)
{
}

void HistoryPage::updateTableData(CWallet* wallet)
{
    std::cout << "updateTableData: updating" << std::endl;
    ui->tableView->setRowCount(0);
    auto txs = WalletUtil::getTXs(wallet);
    for (int row = 0; row < (short)txs.size(); row++) {
        ui->tableView->insertRow(row);
        int col = 0;
        for (QString dataName : {"date", "type", "address", "amount"}) {
            QString data = txs[row].at(dataName);
            QString date = data;
            QTableWidgetItem* cell = new QTableWidgetItem();
            switch (col) {
                case 0: /*date*/
                    cell->setData(0, date);
                    break;
                default:
                    cell->setData(0, data);
                    break;
            }
            ui->tableView->setItem(row, col, cell);
            col++;
        }
    }
    ui->tableView->setVisible(ui->tableView->rowCount());
}

void HistoryPage::updateAddressBookData(CWallet* wallet)
{
    ui->lineEditDesc->clear();
    ui->lineEditDesc->addItem(allAddressString);
    QList<QString> addresses = WalletUtil::getAddressBookData(wallet);
    for (QString address : addresses)
        ui->lineEditDesc->addItem(address);
    ui->lineEditDesc->lineEdit()->setText(QString(""));
}

void HistoryPage::updateFilter()
{
    std::cout << "updateFilter: updating" << std::endl;
    syncTime(ui->dateTimeEditFrom, timeEditFrom);
    syncTime(ui->dateTimeEditFrom, timeEditFrom);
    auto selectedAmount = ui->lineEditAmount->text().toFloat();
    QString selectedType = ui->comboBoxType->currentText();
    QList<QString> selectedAddresses = ui->lineEditDesc->lineEdit()->text().split(" | ");

    for (int row = 0; row < ui->tableView->rowCount(); row++) {
        bool hide = false;
        QDateTime date = QDateTime::fromString(ui->tableView->item(row, 0)->text(), "M/d/yyyy h:m");
        QString type = ui->tableView->item(row, 1)->text();
        QString address = ui->tableView->item(row, 2)->text();
        auto amount = ui->tableView->item(row, 3)->text().toFloat();

        if (
            (ui->dateTimeEditFrom->dateTime() > date) || (ui->dateTimeEditTo->dateTime() < date) || //record is not between selected dates

            (amount < selectedAmount) //record smaller than selected min amount
        )
            hide = true;
        if (selectedType != tr("All Types")) {
            if (selectedType == tr("Received")) {
                hide = !(type == tr("Received") || type == tr("Masternode Reward") || type == tr("Staking Reward") || type == ("PoA Reward"));
            } else
                hide = (selectedType != type) || hide;
        }
        if (ui->lineEditDesc->currentText() != allAddressString) {
            bool found = false;
            for (QString selectedAddress : selectedAddresses)
                if (address.contains(selectedAddress))
                    found = true;
            hide = !found || hide;
        }

        ui->tableView->setRowHidden(row, false);
    }
}

void HistoryPage::syncTime(QDateTimeEdit* calendar, QTimeEdit* clock)
{
    calendar->setTime(clock->time());
}

void HistoryPage::txalert(QString a, int b, CAmount c, QString d, QString e){
    //updateTableData(pwalletMain);
    //ui->tableView->setRowCount(0);
    //auto txs = WalletUtil::getTXs(wallet);
    //for (int row = 0; row < (short)txs.size(); row++) {
    ui->tableView->setSortingEnabled(false);
    int row = ui->tableView->rowCount();
    ui->tableView->insertRow(row);
    int col = 0;
    QStringList splits = d.split(" ");
    QString type = splits[0];
    QString addr = e.trimmed().mid(1, e.trimmed().length() - 2);
    for (QString dataName : {"date", "type", "address", "amount"}) {
        QTableWidgetItem* cell = new QTableWidgetItem();
        switch (col) {

            case 0: /*date*/
                cell->setData(0, a);
                    break;
                case 1: /*type*/

                    cell->setData(0, type);
                    break;
                case 2: /*address*/
                    cell->setData(0, addr);
                    break;
                case 3: /*amount*/
                    cell->setData(0, BitcoinUnits::format(0, c));
                    break;
                /*default:
                    cell->setData(0, data);
                    break;*/
            }
            ui->tableView->setItem(row, col, cell);
            col++;
            ui->tableView->update();
        }
    //}
    ui->tableView->setSortingEnabled(true);
    ui->tableView->setVisible(ui->tableView->rowCount());
    ui->tableView->update();
    ui->tableView->viewport()->update();
}