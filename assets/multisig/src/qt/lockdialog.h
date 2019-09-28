#ifndef LOCKDIALOG_H
#define LOCKDIALOG_H

#include <QDialog>
#include <QSettings>

class WalletModel;

namespace Ui {
class LockDialog;
}

class LockDialog : public QDialog
{
    Q_OBJECT

public:
    explicit LockDialog(QWidget *parent = 0);
    ~LockDialog();

    void setModel(WalletModel* model);

private slots:
    void on_lock();

private:
    Ui::LockDialog *ui;
    WalletModel* model;
    QSettings settings;
};

#endif // LOCKDIALOG_H
