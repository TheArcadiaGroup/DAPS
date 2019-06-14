#ifndef ENCRYPTDIALOG_H
#define ENCRYPTDIALOG_H

#include "walletmodel.h"
#include <QDialog>

namespace Ui {
class EncryptDialog;
}

class EncryptDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EncryptDialog(QWidget *parent = 0);
    ~EncryptDialog();

    void setModel(WalletModel* model);
    bool matchNewPasswords();

private slots:
	void on_acceptPassphrase();
	void validateNewPass();
    void validateNewPassRepeat();

private:
    Ui::EncryptDialog *ui;
    WalletModel* model;
};

#endif // ENCRYPTDIALOG_H
