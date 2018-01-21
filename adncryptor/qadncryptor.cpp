#include "adncryptor.h"
#include <QThread>
#include <QTimer>
#include <QDebug>

#define FREE_MEMORY(x) if(x != NULL){delete x; x = NULL;} //Antony

class QADNCryptor::ADNCryptorThread : public QThread
{
    Q_OBJECT

    ADNCryptor* m_cryptor;
    int direction = 0;
    QTimer* m_progressTimer;

signals:
    void progress(int percent);
    void encryptionDone(bool result);
    void decryptionDone(bool result);

public:
    explicit ADNCryptorThread(ADNCryptor* cryptor)
    {
        m_cryptor = cryptor;
        m_progressTimer = new QTimer(this);
        connect(m_progressTimer,SIGNAL(timeout()),this,SLOT(onTimer()));
        m_progressTimer->setInterval(1000);
    }

    virtual ~ADNCryptorThread()
    {
        FREE_MEMORY(m_progressTimer);
        FREE_MEMORY(m_cryptor);
    }

    void startEncryption()
    {
        direction = 0;
        m_progressTimer->start();
        start();
    }

    void startDecryption()
    {
        direction = 1;
        m_progressTimer->start();
        start();
    }

    // QThread interface
protected:
    void run()
    {
        bool result;

        if(direction == 0)
        {
            result = m_cryptor->Encrypt();
            emit encryptionDone(result);
        }
        else
        {
            result = m_cryptor->Decrypt();
            emit decryptionDone(result);
        }

        return;
    }

private slots:
    void onTimer()
    {
        quint64 totalBytes = m_cryptor->TotalBytes();

        if(totalBytes == 0)
        {
            emit progress(0);
            return;
        }

        quint64 processedBytes = m_cryptor->ProcessedBytes();

        if(processedBytes == 0)
        {
            emit progress(0);
            return;
        }

        float diff = ((float)processedBytes/(float)totalBytes);
        int percent = diff * 100.0;
        emit progress(percent);
        return;
    }
};

QADNCryptor::QADNCryptor(QString encryptedFile, QString decryptedFile, ADNCryptor::CryptType type, QString key)
{
    cryptor = new ADNCryptor(encryptedFile,decryptedFile,type,key);
    m_cryptorThread = new ADNCryptorThread(cryptor);
    connect(m_cryptorThread,SIGNAL(progress(int)),this,SIGNAL(progress(int)));
    connect(m_cryptorThread,SIGNAL(encryptionDone(bool)),this,SIGNAL(encryptionFinished(bool)));
    connect(m_cryptorThread,SIGNAL(decryptionDone(bool)),this,SIGNAL(decryptionFinished(bool)));
}

QADNCryptor::~QADNCryptor()
{
    FREE_MEMORY(cryptor);
    FREE_MEMORY(m_cryptorThread);
}

void QADNCryptor::StartEncryption()
{
    m_cryptorThread->startEncryption();
}

void QADNCryptor::StartDecryption()
{
    m_cryptorThread->startDecryption();
}

#include "qadncryptor.moc"
#include "moc_adncryptor.cpp"
