#ifndef ADNCRYPTOR_H
#define ADNCRYPTOR_H

#include <QtCore/qglobal.h>

#if defined(ADNCRYPTOR_LIBRARY)
#  define ADNCRYPTORSHARED_EXPORT Q_DECL_EXPORT
#else
#  define ADNCRYPTORSHARED_EXPORT Q_DECL_IMPORT
#endif

#include <QString>
#include <QObject>

class ADNCRYPTORSHARED_EXPORT ADNCryptor
{
public:
    enum CryptType{XOR = 0,BINARY,BLOCK};

public:
    ADNCryptor();
    ADNCryptor(QString encryptedFile, QString decryptedFile, CryptType type = XOR, QString key = QString());
    ~ADNCryptor();

public:
    bool Encrypt();
    bool Decrypt();
    quint64 TotalBytes();
    quint64 ProcessedBytes();
    QString key() const;

public:
    static void GenerateRSAKey(const char *privFilename, const char *pubFilename, const char *password);
    static std::string RSAEncryptString(const char *pubFilename, const char *password, const char *string);
    static std::string RSADecryptString(const char *privFilename, const char *string);
    static void RSASignFile(const char *privFilename, const char *Filename, const char *signatureFilename);
    static bool RSAVerifyFile(const char *pubFilename, const char *Filename, const char *signatureFilename);
    static QString GetDefaultKey();

private:
    struct ADNCryptorPrivate;
    ADNCryptorPrivate* _cryptor;
};

class ADNCRYPTORSHARED_EXPORT QADNCryptor : public QObject
{
    Q_OBJECT

public:
    QADNCryptor(QString encryptedFile, QString decryptedFile, ADNCryptor::CryptType type = ADNCryptor::XOR, QString key = QString());
    ~QADNCryptor();

public:
    void StartEncryption();
    void StartDecryption();

private:
    ADNCryptor* cryptor;

signals:
    void encryptionFinished(bool result);
    void decryptionFinished(bool result);
    void progress(int percent);

private:
    class ADNCryptorThread;
    ADNCryptorThread* m_cryptorThread;
};

#endif // ADNCRYPTOR_H
