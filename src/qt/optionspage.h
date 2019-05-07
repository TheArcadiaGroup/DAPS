// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OPTIONSPAGE_H
#define BITCOIN_QT_OPTIONSPAGE_H

#include "guiutil.h"
#include "togglebutton.h"

#include <QDialog>
#include <QHeaderView>
#include <QItemSelection>
#include <QKeyEvent>
#include <QMenu>
#include <QPoint>
#include <QVariant>
#include <QSettings>
#include <QSizeGrip>
#include <togglebutton.h>

class OptionsModel;
class WalletModel;
class BitcoinGUI;

namespace Ui
{
class OptionsPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for options page */
class OptionsPage : public QDialog
{
    Q_OBJECT

public:
    explicit OptionsPage(QWidget* parent = 0);
    ~OptionsPage();

    void setModel(WalletModel* model);
    void setMapper();
    bool matchNewPasswords();
    void bitcoinGUIInstallEvent(BitcoinGUI *gui);

public slots:
	void on_EnableStaking(ToggleButton*);

protected:
    virtual void keyPressEvent(QKeyEvent* event);

private:
    Ui::OptionsPage* ui;
    GUIUtil::TableViewLastColumnResizingFixer* columnResizingFixer;
    WalletModel* model;
    OptionsModel* options;
    QDataWidgetMapper* mapper;
    QSettings settings;
    QSizeGrip m_SizeGrip;
    QMenu* contextMenu;
    virtual void resizeEvent(QResizeEvent* event);
    CAmount getValidatedAmount();

private slots:
    void validateNewPass();
    void validateNewPassRepeat();
    void onOldPassChanged();
//    void on_pushButtonDarkMode_clicked();
//    void on_pushButtonLightMode_clicked();
    void on_pushButtonPassword_clicked();
    void on_pushButtonBackup_clicked();
    void changeTheme(ToggleButton* widget);
    void on_pushButtonSave_clicked();
};

#endif // BITCOIN_QT_OPTIONSPAGE_H
