#ifndef QGOOGLEAUTH_H
#define QGOOGLEAUTH_H

#include <QString>

class QGoogleAuth {
public:
    explicit QGoogleAuth();
    static QByteArray hmacSha1(QByteArray key, QByteArray baseString);
    static int base32_decode(const quint8 *encoded, quint8 *result, int bufSize);
    static QString generatePin(const QByteArray key);
};

#endif // QGOOGLEAUTH_H
