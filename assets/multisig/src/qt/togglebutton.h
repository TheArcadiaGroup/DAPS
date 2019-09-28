// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TOGGLEBUTTON_H
#define BITCOIN_QT_TOGGLEBUTTON_H

#include <QWidget>


namespace Ui
{
class ToggleButton;
}

class ToggleButton : public QWidget
{
    Q_OBJECT

public:
    explicit ToggleButton(QWidget* parent = 0);
    ~ToggleButton();
    void setOptionA(QString label);
    void setOptionB(QString label);
    void setLayoutDirection(Qt::LayoutDirection Dir);
    bool getState();
    void setState(bool value);

protected:
    void resizeEvent(QResizeEvent * event);
    void paintEvent(QPaintEvent *);

public slots:
    void toggle();

signals:
    void stateChanged(ToggleButton* widget);
private slots:

private:
    Ui::ToggleButton* ui;
    Qt::LayoutDirection direction;
    bool state;
    void update();
    void resize();
};

#endif // BITCOIN_QT_TOGGLEBUTTON_H
