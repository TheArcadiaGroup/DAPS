#ifndef TWOFADIALOG_H
#define TWOFADIALOG_H

#include <QDialog>
#include <QSettings>

namespace Ui {
class TwoFADialog;
}

class TwoFADialog : public QDialog
{
    Q_OBJECT

public:
    explicit TwoFADialog(QWidget *parent = 0);
    ~TwoFADialog();

private slots:
    void on_acceptCode();
    void codeChanged(const QString & txt);

private:
    Ui::TwoFADialog *ui;
    QSettings settings;
};

#endif // TWOFADIALOG_H
