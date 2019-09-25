#ifndef IMPROTORCREATE_H
#define IMPROTORCREATE_H

#include <QDialog>
#include <QSettings>

class WalletModel;

namespace Ui {
class ImportOrCreate;
}

class ImportOrCreate : public QDialog
{
    Q_OBJECT

public:
    explicit ImportOrCreate(QWidget *parent = 0);
    ~ImportOrCreate();
    bool willRecover = false;
private slots:
    void on_next();

private:
    Ui::ImportOrCreate *ui;
    QSettings settings;
};

#endif // IMPROTORCREATE_H
