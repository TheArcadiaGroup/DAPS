#ifndef UNLOCKDIALOG_H
#define UNLOCKDIALOG_H

#include <QDialog>
#include <QSettings>

class WalletModel;

namespace Ui {
class UnlockDialog;
}

class UnlockDialog : public QDialog
{
    Q_OBJECT

public:
    explicit UnlockDialog(QWidget *parent = 0);
    ~UnlockDialog();

    void setModel(WalletModel* model);

private slots:
    void on_unlock();

private:
    Ui::UnlockDialog *ui;
    WalletModel* model;
    QSettings settings;
};

#endif // UNLOCKDIALOG_H
