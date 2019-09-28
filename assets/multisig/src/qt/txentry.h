// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TXENTRY_H
#define BITCOIN_QT_TXENTRY_H

#include "walletmodel.h"

#include <QWidget>

class WalletModel;

namespace Ui
{
class TxEntry;
}

class TxEntry : public QWidget
{
    Q_OBJECT

public:
    explicit TxEntry(QWidget* parent = 0);
    ~TxEntry();

    void setData(int64_t Date, QString Address, QString Amount, QString ID, QString Type);
    void expand(bool isExpanding);

protected:
    void resizeEvent(QResizeEvent *event);

public slots:

signals:

private slots:
void on_pushButtonExpand_clicked();

private:
    Ui::TxEntry* ui;
    WalletModel* model;
    void init();
};

#endif // BITCOIN_QT_TXENTRY_H
