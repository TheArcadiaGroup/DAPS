/********************************************************************************
** Form generated from reading UI file 'multisigsetupaddsigner.ui'
**
** Created by: Qt User Interface Compiler version 5.13.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MULTISIGSETUPADDSIGNER_H
#define UI_MULTISIGSETUPADDSIGNER_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_MultiSigSetupAddSigner
{
public:
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QLabel *label_2;
    QTextEdit *textComboKey;
    QHBoxLayout *horizontalLayout_5;
    QPushButton *btnBack;
    QPushButton *btnNext;

    void setupUi(QDialog *MultiSigSetupAddSigner)
    {
        if (MultiSigSetupAddSigner->objectName().isEmpty())
            MultiSigSetupAddSigner->setObjectName(QString::fromUtf8("MultiSigSetupAddSigner"));
        MultiSigSetupAddSigner->resize(611, 243);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MultiSigSetupAddSigner->sizePolicy().hasHeightForWidth());
        MultiSigSetupAddSigner->setSizePolicy(sizePolicy);
        verticalLayout = new QVBoxLayout(MultiSigSetupAddSigner);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        verticalLayout->setContentsMargins(-1, 30, -1, -1);
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(MultiSigSetupAddSigner);
        label->setObjectName(QString::fromUtf8("label"));
        label->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);

        horizontalLayout->addWidget(label);


        verticalLayout->addLayout(horizontalLayout);

        label_2 = new QLabel(MultiSigSetupAddSigner);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        QFont font;
        font.setPointSize(9);
        label_2->setFont(font);

        verticalLayout->addWidget(label_2);

        textComboKey = new QTextEdit(MultiSigSetupAddSigner);
        textComboKey->setObjectName(QString::fromUtf8("textComboKey"));

        verticalLayout->addWidget(textComboKey);

        horizontalLayout_5 = new QHBoxLayout();
        horizontalLayout_5->setSpacing(100);
        horizontalLayout_5->setObjectName(QString::fromUtf8("horizontalLayout_5"));
        horizontalLayout_5->setContentsMargins(100, -1, 100, -1);
        btnBack = new QPushButton(MultiSigSetupAddSigner);
        btnBack->setObjectName(QString::fromUtf8("btnBack"));

        horizontalLayout_5->addWidget(btnBack);

        btnNext = new QPushButton(MultiSigSetupAddSigner);
        btnNext->setObjectName(QString::fromUtf8("btnNext"));

        horizontalLayout_5->addWidget(btnNext);


        verticalLayout->addLayout(horizontalLayout_5);


        retranslateUi(MultiSigSetupAddSigner);

        QMetaObject::connectSlotsByName(MultiSigSetupAddSigner);
    } // setupUi

    void retranslateUi(QDialog *MultiSigSetupAddSigner)
    {
        MultiSigSetupAddSigner->setWindowTitle(QCoreApplication::translate("MultiSigSetupAddSigner", "Multisignature Wallet Setup", nullptr));
        label->setText(QCoreApplication::translate("MultiSigSetupAddSigner", "My Combo Key (1 of 5)", nullptr));
        label_2->setText(QCoreApplication::translate("MultiSigSetupAddSigner", "This is your combo key, consisting of your multisignature keychain wallet's public spend key, \n"
"and private view key. Send this combo key to your n co-signers", nullptr));
        btnBack->setText(QCoreApplication::translate("MultiSigSetupAddSigner", "Back", nullptr));
#if QT_CONFIG(shortcut)
        btnBack->setShortcut(QCoreApplication::translate("MultiSigSetupAddSigner", "Esc", nullptr));
#endif // QT_CONFIG(shortcut)
        btnNext->setText(QCoreApplication::translate("MultiSigSetupAddSigner", "Next", nullptr));
#if QT_CONFIG(shortcut)
        btnNext->setShortcut(QCoreApplication::translate("MultiSigSetupAddSigner", "Return", nullptr));
#endif // QT_CONFIG(shortcut)
    } // retranslateUi

};

namespace Ui {
    class MultiSigSetupAddSigner: public Ui_MultiSigSetupAddSigner {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MULTISIGSETUPADDSIGNER_H
