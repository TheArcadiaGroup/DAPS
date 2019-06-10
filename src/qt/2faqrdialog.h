#ifndef TWOFAQRDIALOG_H
#define TWOFAQRDIALOG_H

#include <QDialog>

class WalletModel;

namespace Ui {
class TwoFAQRDialog;
}

class TwoFAQRDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TwoFAQRDialog(QWidget *parent = 0);
    ~TwoFAQRDialog();

    void setModel(WalletModel* model);

private:
    void update();

private slots:
    void on_btnCopyURI_clicked();


private:
    Ui::TwoFAQRDialog *ui;
    WalletModel* model;
};

#endif // TWOFAQRDIALOG_H