#ifndef ENTERMNEMONICS_H
#define ENTERMNEMONICS_H

#include <QDialog>
#include <QSettings>

class WalletModel;

namespace Ui {
class EnterMnemonics;
}

class EnterMnemonics : public QDialog
{
    Q_OBJECT

public:
    explicit EnterMnemonics(QWidget *parent = 0);
    ~EnterMnemonics();
private slots:
    void on_next();

private:
    Ui::EnterMnemonics *ui;
    QSettings settings;
};

#endif // ENTERMNEMONICS_H
