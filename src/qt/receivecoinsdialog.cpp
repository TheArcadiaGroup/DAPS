// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receivecoinsdialog.h"
#include "ui_receivecoinsdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
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

ReceiveCoinsDialog::ReceiveCoinsDialog(QWidget* parent) : QDialog(parent),
                                                          ui(new Ui::ReceiveCoinsDialog),
                                                          model(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    // #REMOVE ui->clearButton->setIcon(QIcon());
    ui->receiveButton->setIcon(QIcon());
    // #REMOVE ui->showRequestButton->setIcon(QIcon());
    // #REMOVE ui->removeRequestButton->setIcon(QIcon());
#endif

    // context menu actions
    QAction* copyLabelAction = new QAction(tr("Copy label"), this);
    QAction* copyMessageAction = new QAction(tr("Copy message"), this);
    QAction* copyAmountAction = new QAction(tr("Copy amount"), this);

    // context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyMessageAction);
    contextMenu->addAction(copyAmountAction);

    // context menu signals
    // #REMOVE connect(ui->recentRequestsView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showMenu(QPoint)));
    connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(copyLabel()));
    connect(copyMessageAction, SIGNAL(triggered()), this, SLOT(copyMessage()));
    connect(copyAmountAction, SIGNAL(triggered()), this, SLOT(copyAmount()));

    // #REMOVE connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));
}

void ReceiveCoinsDialog::setModel(WalletModel* model)
{
    this->model = model;

    if (model && model->getOptionsModel()) {
        model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        updateDisplayUnit();

        loadAccount();
        // #REMOVE QTableView* tableView = ui->recentRequestsView;

        // #REMOVE tableView->verticalHeader()->hide();
        // #REMOVE tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        // #REMOVE tableView->setModel(model->getRecentRequestsTableModel());
        // #REMOVE tableView->setAlternatingRowColors(true);
        // #REMOVE tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        // #REMOVE tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        // #REMOVE tableView->setColumnWidth(RecentRequestsTableModel::Date, DATE_COLUMN_WIDTH);
        // #REMOVE tableView->setColumnWidth(RecentRequestsTableModel::Label, LABEL_COLUMN_WIDTH);

        // #REMOVE connect(tableView->selectionModel(),
        // #REMOVE     SIGNAL(selectionChanged(QItemSelection, QItemSelection)), this,
        // #REMOVE     SLOT(recentRequestsView_selectionChanged(QItemSelection, QItemSelection)));
        // Last 2 columns are set by the columnResizingFixer, when the table geometry is ready.
        // #REMOVE columnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(tableView, AMOUNT_MINIMUM_COLUMN_WIDTH, DATE_COLUMN_WIDTH);
    }
}

void ReceiveCoinsDialog::loadAccount() {
    //Set reqAddress as the master stealth address
    std::vector<std::string> addrList, accountList;
    CWallet* wl = model->getCWallet();
    QList<QString> stringsList;
    wl->AllMyPublicAddresses(addrList, accountList);
    for(int i = 0; i < addrList.size(); i++) {
        stringsList.append(QString(accountList[i].c_str()) + " - " + QString(addrList[i].c_str()));
    }

    ui->reqAddress->addItems(stringsList);
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    ui->reqAmount->clear();
    // #REMOVE ui->reqLabel->setText("");
    // #REMOVE ui->reqMessage->setText("");
    // #REMOVE ui->reuseAddress->setChecked(false);
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
    if (model && model->getOptionsModel()) {
        ui->reqAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    if (!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    std::vector<std::string> addrList, accountList;
    CWallet* wl = model->getCWallet();
    wl->AllMyPublicAddresses(addrList, accountList);
    int selectedIdx = ui->reqAddress->currentIndex();
    if (addrList.size()>selectedIdx){
        QString address(addrList[selectedIdx].c_str());
        QString label(accountList[selectedIdx].c_str());
        QString reqMes = "Request message";
        QString strPaymentID = ui->reqID->text();
        if (!strPaymentID.trimmed().isEmpty()) {
            quint64 paymentID = strPaymentID.toULongLong();
            uint64_t id = paymentID;
            std::string integratedAddr;
            if (selectedIdx == 0) {
                wl->ComputeIntegratedPublicAddress(id, "masteraccount", integratedAddr);
            } else {
                wl->ComputeIntegratedPublicAddress(id, accountList[selectedIdx], integratedAddr);
            }
            address = QString(integratedAddr.c_str());
        }

        SendCoinsRecipient info(address, label,
            ui->reqAmount->value(), reqMes);
        ReceiveRequestDialog* dialog = new ReceiveRequestDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setModel(model->getOptionsModel());
        dialog->setInfo(info);
        dialog->show();
        clear();
        model->getRecentRequestsTableModel()->addNewRequest(info);
    }

}

void ReceiveCoinsDialog::on_recentRequestsView_doubleClicked(const QModelIndex& index)
{
    // #REMOVE const RecentRequestsTableModel* submodel = model->getRecentRequestsTableModel();
    // #REMOVE ReceiveRequestDialog* dialog = new ReceiveRequestDialog(this);
    // #REMOVE dialog->setModel(model->getOptionsModel());
    // #REMOVE dialog->setInfo(submodel->entry(index.row()).recipient);
    // #REMOVE dialog->setAttribute(Qt::WA_DeleteOnClose);
    // #REMOVE dialog->show();
}

void ReceiveCoinsDialog::recentRequestsView_selectionChanged(const QItemSelection& selected, const QItemSelection& deselected)
{
    // Enable Show/Remove buttons only if anything is selected.
    // #REMOVE bool enable = !ui->recentRequestsView->selectionModel()->selectedRows().isEmpty();
    // #REMOVE ui->showRequestButton->setEnabled(enable);
    // #REMOVE ui->removeRequestButton->setEnabled(enable);
}

void ReceiveCoinsDialog::on_showRequestButton_clicked()
{
    // #REMOVE if (!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
    // #REMOVE     return;
    // #REMOVE QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();

    // #REMOVE foreach (QModelIndex index, selection) {
    // #REMOVE     on_recentRequestsView_doubleClicked(index);
    // #REMOVE }
}

void ReceiveCoinsDialog::on_removeRequestButton_clicked()
{
    // #REMOVE if (!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
    // #REMOVE     return;
    // #REMOVE QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    // #REMOVE if (selection.empty())
    // #REMOVE     return;
    // correct for selection mode ContiguousSelection
    // #REMOVE QModelIndex firstIndex = selection.at(0);
    // #REMOVE model->getRecentRequestsTableModel()->removeRows(firstIndex.row(), selection.length(), firstIndex.parent());
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void ReceiveCoinsDialog::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    // #REMOVE columnResizingFixer->stretchColumnWidth(RecentRequestsTableModel::Message);
}

void ReceiveCoinsDialog::keyPressEvent(QKeyEvent* event)
{
    if (event->key() == Qt::Key_Return) {
        // press return -> submit form
        if (ui->reqAddress->hasFocus() || ui->reqAmount->hasFocus() || ui->reqID->hasFocus()) {
            event->ignore();
            on_receiveButton_clicked();
            return;
        }
    }

    this->QDialog::keyPressEvent(event);
}

// copy column of selected row to clipboard
void ReceiveCoinsDialog::copyColumnToClipboard(int column)
{
    // #REMOVE if (!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
    // #REMOVE     return;
    // #REMOVE QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    // #REMOVE if (selection.empty())
    // #REMOVE     return;
    // correct for selection mode ContiguousSelection
    // #REMOVE QModelIndex firstIndex = selection.at(0);
    // #REMOVE GUIUtil::setClipboard(model->getRecentRequestsTableModel()->data(firstIndex.child(firstIndex.row(), column), Qt::EditRole).toString());
}

// context menu
void ReceiveCoinsDialog::showMenu(const QPoint& point)
{
    // #REMOVE if (!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
    // #REMOVE     return;
    // #REMOVE QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    // #REMOVE if (selection.empty())
    // #REMOVE     return;
    // #REMOVE contextMenu->exec(QCursor::pos());
}

// context menu action: copy label
void ReceiveCoinsDialog::copyLabel()
{
    // #REMOVE copyColumnToClipboard(RecentRequestsTableModel::Label);
}

// context menu action: copy message
void ReceiveCoinsDialog::copyMessage()
{
    // #REMOVE copyColumnToClipboard(RecentRequestsTableModel::Message);
}

// context menu action: copy amount
void ReceiveCoinsDialog::copyAmount()
{
    // #REMOVE copyColumnToClipboard(RecentRequestsTableModel::Amount);
}
