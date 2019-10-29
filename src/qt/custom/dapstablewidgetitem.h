#ifndef DAPSTABLEWIDGETITEM_H
#define DAPSTABLEWIDGETITEM_H
#include <QTableWidget>
#include <QVariant>
#include <QString>
#include <QDateTime>

class DAPSTableWidgetItem : public QTableWidgetItem {
    public:
        bool operator <(const QTableWidgetItem &other) const
        {
            QVariant l(text()), r(other.text());
            QString format = "MM/dd/yy HH:mm:ss";
            QDateTime dtl;
            QDateTime dtr;
            switch (l.type())
            {
            case QVariant::Invalid:
                return (r.type() == QVariant::Invalid);
            case QVariant::Int:
                return l.toInt() < r.toInt();
            case QVariant::UInt:
                return l.toUInt() < r.toUInt();
            case QVariant::LongLong:
                return l.toLongLong() < r.toLongLong();
            case QVariant::ULongLong:
                return l.toULongLong() < r.toULongLong();
            case QVariant::Double:
                return l.toDouble() < r.toDouble();
            case QVariant::Char:
                return l.toChar() < r.toChar();
            case QVariant::Date:
                return l.toDate() < r.toDate();
            case QVariant::Time:
                return l.toTime() < r.toTime();
            case QVariant::DateTime:
                dtl = QDateTime::fromString (l.toString(), format);
                dtr = QDateTime::fromString (r.toString(), format);
                return dtl < dtr;
            case QVariant::String:
            default:
                return l.toString().compare(r.toString(), Qt::CaseSensitive) < 0;
            }
            return false;
        }
};

#endif 
