#ifndef TWOFACONFIRMDIALOG_H
#define TWOFACONFIRMDIALOG_H

#include <QDialog>
#include <QSettings>

namespace Ui {
class TwoFAConfirmDialog;
}

class TwoFAConfirmDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TwoFAConfirmDialog(QWidget *parent = 0);
    ~TwoFAConfirmDialog();

private slots:
    void on_acceptCode();
    void codeChanged(const QString & txt);

private:
    Ui::TwoFAConfirmDialog *ui;
    QSettings settings;
};

#endif // TWOFACONFIRMDIALOG_H
