#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "adncryptor.h"
#include "cryptlib.h"
#include "factory.h"
#include "modes.h"
#include "dh.h"
#include "esign.h"
#include "md2.h"
#include "rw.h"
#include "md5.h"
#include "rsa.h"
#include "ripemd.h"
#include "dsa.h"
#include "seal.h"
#include "whrlpool.h"
#include "ttmac.h"
#include "camellia.h"
#include "shacal2.h"
#include "tea.h"
#include "panama.h"
#include "pssr.h"
#include "aes.h"
#include "salsa.h"
#include "vmac.h"
#include "tiger.h"
#include "md5.h"
#include "sosemanuk.h"
#include "arc4.h"
#include "ccm.h"
#include "gcm.h"
#include "eax.h"
#include "twofish.h"
#include "serpent.h"
#include "cast.h"
#include "rc6.h"
#include "mars.h"
#include "des.h"
#include "idea.h"
#include "rc5.h"
#include "tea.h"
#include "skipjack.h"
#include "cmac.h"
#include "dmac.h"
#include "blowfish.h"
#include "seed.h"
#include "wake.h"
#include "seal.h"
#include "crc.h"
#include "adler32.h"
#include "files.h"
#include "osrng.h"
#include "socketft.h"
#include "wait.h"
#include "hex.h"

#include <QFile>
#include <QDataStream>
#include <QDebug>
#include <QTime>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <sstream>
#include <string>
#include <locale>
#include <time.h>

#define KEY_LENGTH 1024
#define ENCRYPTION_KEY_LENGTH 8

#define FREE_MEMORY(x) if(x != NULL){delete x; x = NULL;} //Antony

#define DEFAULT_KEY "Antony.Nadar.007"
#define DEFAULT_KEY_MASK "472672462762624672164216712671267276126471241264126421654126512672651726172561671657"

#if CRYPTOPP_GCC_DIAGNOSTIC_AVAILABLE
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

namespace { OFB_Mode<AES>::Encryption s_globalRNG; }
RandomNumberGenerator & GlobalRNG()
{
    return dynamic_cast<RandomNumberGenerator&>(s_globalRNG);
}

struct ADNCryptor::ADNCryptorPrivate{
    ADNCryptor::CryptType m_type;
    QString m_encryptedFile;
    QString m_decryptedFile;
    QString m_key;
    quint64 bytesProccessed = 0;
    quint64 bytesTotal = 0;

    ADNCryptorPrivate()
    {
        init();
    }

    ADNCryptorPrivate(QString encryptedFile, QString decryptedFile, ADNCryptor::CryptType type, QString key):m_type(type),m_encryptedFile(encryptedFile),m_decryptedFile(decryptedFile),m_key(key)
    {
        if(m_key == DEFAULT_KEY_MASK)
            m_key = DEFAULT_KEY;

        if(m_key.isEmpty())
            generateKey();

        init();
    }

    void init()
    {
#ifdef _CRTDBG_LEAK_CHECK_DF
        // Turn on leak-checking
        int tempflag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );
        tempflag |= _CRTDBG_LEAK_CHECK_DF;
        _CrtSetDbgFlag( tempflag );
#endif
        RegisterFactories();
    }

    void RegisterFactories()
    {
        static bool s_registered = false;
        if (s_registered)
            return;

        std::string cSeed = IntToString(time(nullptr));
        cSeed.resize(16, ' ');

        OFB_Mode<AES>::Encryption& aesg = dynamic_cast<OFB_Mode<AES>::Encryption&>(GlobalRNG());
        aesg.SetKeyWithIV((byte *)cSeed.data(), 16, (byte *)cSeed.data());

        RegisterDefaultFactoryFor<SimpleKeyAgreementDomain, DH>();
        RegisterDefaultFactoryFor<HashTransformation, CRC32>();
        RegisterDefaultFactoryFor<HashTransformation, Adler32>();
        RegisterDefaultFactoryFor<HashTransformation, Weak::MD5>();
        RegisterDefaultFactoryFor<HashTransformation, SHA1>();
        RegisterDefaultFactoryFor<HashTransformation, SHA224>();
        RegisterDefaultFactoryFor<HashTransformation, SHA256>();
        RegisterDefaultFactoryFor<HashTransformation, SHA384>();
        RegisterDefaultFactoryFor<HashTransformation, SHA512>();
        RegisterDefaultFactoryFor<HashTransformation, Whirlpool>();
        RegisterDefaultFactoryFor<HashTransformation, Tiger>();
        RegisterDefaultFactoryFor<HashTransformation, RIPEMD160>();
        RegisterDefaultFactoryFor<HashTransformation, RIPEMD320>();
        RegisterDefaultFactoryFor<HashTransformation, RIPEMD128>();
        RegisterDefaultFactoryFor<HashTransformation, RIPEMD256>();
        RegisterDefaultFactoryFor<HashTransformation, Weak::PanamaHash<LittleEndian> >();
        RegisterDefaultFactoryFor<HashTransformation, Weak::PanamaHash<BigEndian> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<Weak::MD5> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA1> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<RIPEMD160> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA224> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA256> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA384> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA512> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, TTMAC>();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, VMAC<AES> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, VMAC<AES, 64> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, Weak::PanamaMAC<LittleEndian> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, Weak::PanamaMAC<BigEndian> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, CMAC<AES> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, DMAC<AES> >();
        RegisterDefaultFactoryFor<MessageAuthenticationCode, CMAC<DES_EDE3> >();
        RegisterAsymmetricCipherDefaultFactories<RSAES<OAEP<SHA1> > >("RSA/OAEP-MGF1(SHA-1)");
        RegisterAsymmetricCipherDefaultFactories<DLIES<> >("DLIES(NoCofactorMultiplication, KDF2(SHA-1), XOR, HMAC(SHA-1), DHAES)");
        RegisterSignatureSchemeDefaultFactories<NR<SHA1> >("NR(1363)/EMSA1(SHA-1)");
        RegisterSignatureSchemeDefaultFactories<GDSA<SHA1> >("DSA-1363/EMSA1(SHA-1)");
        RegisterSignatureSchemeDefaultFactories<RSASS<PKCS1v15, Weak::MD2> >("RSA/PKCS1-1.5(MD2)");
        RegisterSignatureSchemeDefaultFactories<RSASS<PKCS1v15, SHA1> >("RSA/PKCS1-1.5(SHA-1)");
        RegisterSignatureSchemeDefaultFactories<ESIGN<SHA1> >("ESIGN/EMSA5-MGF1(SHA-1)");
        RegisterSignatureSchemeDefaultFactories<RWSS<P1363_EMSA2, SHA1> >("RW/EMSA2(SHA-1)");
        RegisterSignatureSchemeDefaultFactories<RSASS<PSS, SHA1> >("RSA/PSS-MGF1(SHA-1)");
        RegisterSymmetricCipherDefaultFactories<SEAL<> >();
        RegisterSymmetricCipherDefaultFactories<ECB_Mode<SHACAL2> >();
        RegisterSymmetricCipherDefaultFactories<ECB_Mode<Camellia> >();
        RegisterSymmetricCipherDefaultFactories<ECB_Mode<TEA> >();
        RegisterSymmetricCipherDefaultFactories<ECB_Mode<XTEA> >();
        RegisterSymmetricCipherDefaultFactories<PanamaCipher<LittleEndian> >();
        RegisterSymmetricCipherDefaultFactories<PanamaCipher<BigEndian> >();
        RegisterSymmetricCipherDefaultFactories<ECB_Mode<AES> >();
        RegisterSymmetricCipherDefaultFactories<CBC_Mode<AES> >();
        RegisterSymmetricCipherDefaultFactories<CFB_Mode<AES> >();
        RegisterSymmetricCipherDefaultFactories<OFB_Mode<AES> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<AES> >();
        RegisterSymmetricCipherDefaultFactories<Salsa20>();
        RegisterSymmetricCipherDefaultFactories<XSalsa20>();
        RegisterSymmetricCipherDefaultFactories<Sosemanuk>();
        RegisterSymmetricCipherDefaultFactories<Weak::MARC4>();
        RegisterSymmetricCipherDefaultFactories<WAKE_OFB<LittleEndian> >();
        RegisterSymmetricCipherDefaultFactories<WAKE_OFB<BigEndian> >();
        RegisterSymmetricCipherDefaultFactories<SEAL<LittleEndian> >();
        RegisterAuthenticatedSymmetricCipherDefaultFactories<CCM<AES> >();
        RegisterAuthenticatedSymmetricCipherDefaultFactories<GCM<AES> >();
        RegisterAuthenticatedSymmetricCipherDefaultFactories<EAX<AES> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<Camellia> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<Twofish> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<Serpent> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<CAST256> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<RC6> >();
        RegisterSymmetricCipherDefaultFactories<ECB_Mode<MARS> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<MARS> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<SHACAL2> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<DES> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<DES_XEX3> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<DES_EDE3> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<IDEA> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<RC5> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<TEA> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<XTEA> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<CAST128> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<SKIPJACK> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<Blowfish> >();
        RegisterSymmetricCipherDefaultFactories<ECB_Mode<SEED> >();
        RegisterSymmetricCipherDefaultFactories<CTR_Mode<SEED> >();

        s_registered = true;
    }

    bool Encrypt()
    {
        return Encrypt(m_decryptedFile, m_encryptedFile);
    }

    bool Encrypt(QString inFile, QString outFile)
    {
        switch (m_type) {
        case ADNCryptor::XOR:
            return encryptByXorMethod(inFile,outFile);
            break;
        case ADNCryptor::BINARY:
            return encryptByBinaryMethod(inFile,outFile);
            break;
        case ADNCryptor::BLOCK:
            return encryptByBlockMethod(inFile,outFile);
            break;
        default:
            break;
        }

        return false;
    }

    bool Decrypt()
    {
        return Decrypt(m_encryptedFile, m_decryptedFile);
    }

    bool Decrypt(QString inFile, QString outFile)
    {
        switch (m_type) {
        case ADNCryptor::XOR:
            return encryptByXorMethod(inFile,outFile);
            break;
        case ADNCryptor::BINARY:
            return decryptByBinaryMethod(inFile,outFile);
            break;
        case ADNCryptor::BLOCK:
            return decryptByBlockMethod(inFile,outFile);
            break;
        default:
            break;
        }

        return false;
    }

    QString key() const
    {
        return m_key;
    }

    void generateKey()
    {
        const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        const int randomStringLength = ENCRYPTION_KEY_LENGTH; // assuming you want random strings of 12 characters

        QString randomString;
        for(int i=0; i<randomStringLength; ++i)
        {
            int index = qrand() % possibleCharacters.length();
            QChar nextChar = possibleCharacters.at(index);
            randomString.append(nextChar);
        }

        m_key = randomString;
    }

    bool encryptByXorMethod(QString inFile, QString outFile)
    {
        FILE* input_file;
        FILE* output_file;

        input_file = fopen(inFile.toStdString().c_str(), "r");
        output_file = fopen(outFile.toStdString().c_str(), "w");

        int key_count = 0; //Used to restart key if strlen(key) < strlen(encrypt)
        int encrypt_byte;

        //Key strings
        char *key = (char*)malloc(sizeof(char) * m_key.length());
        strcpy(key,m_key.toStdString().c_str());

        fseek(input_file, 0L, SEEK_END);
        bytesTotal = std::ftell(input_file);

        rewind(input_file);

        bytesProccessed = 0;

        //Loop through each byte of file until EOF
        while( (encrypt_byte = fgetc(input_file)) != EOF)
        {
            //XOR the data and write it to a file
            fputc(encrypt_byte ^ key[key_count], output_file);

            //Increment key_count and start over if necessary
            key_count++;
            if(key_count == (int)strlen(key))
                key_count = 0;

            bytesProccessed++;
        }

        free(key);
        fclose(input_file);
        fclose(output_file);

        return true;
    }

    bool encryptByBinaryMethod(QString inFile, QString outFile)
    {
        QFile file(inFile);
        QFile extFile(outFile);

        if(!file.open(QIODevice::ReadOnly))
            return false;

        if(!extFile.open(QIODevice::WriteOnly))
            return false;

        QDataStream extStream(&extFile);

        extStream << file.readAll().toHex();

        file.close();
        extFile.close();

        return true;
    }

    bool decryptByBinaryMethod(QString inFile, QString outFile)
    {
        Q_UNUSED(inFile)
        Q_UNUSED(outFile)
        return false;
    }

    bool encryptByBlockMethod(QString inFile, QString outFile)
    {
        byte pass[AES::BLOCKSIZE]; // digest of password
        byte iv[16]; // Initial Vector (IV),  misused
        // by original author
        byte true_iv[16];             // real IV used - set to zero

        CryptoPP::AutoSeededRandomPool rng;

        // digest password
        CryptoPP::StringSource(m_key.toStdString().c_str(), true,new CryptoPP::HashFilter(*(new CryptoPP::SHA256),new CryptoPP::ArraySink(pass, AES::BLOCKSIZE)));

        // random Initial Vector
        rng.GenerateBlock(iv, 16);
        memset(true_iv, 0, 16);

        // create object for encrypting
        CryptoPP::AES::Encryption aesEncryption(pass,CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption,true_iv);

        CryptoPP::StreamTransformationFilter *encryptor;
        encryptor = new CryptoPP::StreamTransformationFilter(cbcEncryption,new CryptoPP::FileSink(outFile.toStdString().c_str()) );

        encryptor->Put(iv, 16); // this prefixes the file with random block (not IV)
        // Cryptographically it is equivalent to IV, so just as good

        // "bind" a file and encrypt one
        CryptoPP::FileSource(inFile.toStdString().c_str(), true, encryptor);

        return true;
    }

    bool decryptByBlockMethod(QString inFile, QString outFile)
    {
        byte pass[AES::BLOCKSIZE];
        byte iv[16];        // here's 1st problem: AES IV is 16 bytes
        byte head_file[16]; // so must skip 16 bytes, not 8.
        Q_UNUSED(head_file)

        memset(iv, 0, 16); // very correct - in fact the encryptor prefixes file
        // with a random block, so no need to pass the IV explicitly.

        try {
            CryptoPP::StringSource(m_key.toStdString().c_str(), true, new CryptoPP::HashFilter(*(new CryptoPP::SHA256), new CryptoPP::ArraySink(pass,AES::BLOCKSIZE)));

            CryptoPP::AES::Decryption aesDecryption(pass, CryptoPP::AES::DEFAULT_KEYLENGTH);
            CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

            CryptoPP::StreamTransformationFilter *decryptor;
            decryptor = new CryptoPP::StreamTransformationFilter(cbcDecryption, new CryptoPP::FileSink(outFile.toStdString().c_str()));


            // decryptor->Get(head_file, 16); // does not do anything useful, wrong here
            // We must somehow decrypt 1st block of the input file, without sending the
            // result into the output file.
            char garbage[16], iv_garbage[16]; // place for IV stuff
            std::ifstream inf;
            inf.open(inFile.toStdString().c_str(),  std::ifstream::binary); inf.read(iv_garbage, 16); // absorb random prefix

            // Decrypt random prefix (with zero IV) to some dummy buffer to get
            // (a) decryptor state adjusted to IV, and
            // (b) file position pointer advanced to the past-IV spot.
            cbcDecryption.ProcessData((byte *)garbage, (const byte *)iv_garbage, 16);

            // NOW can run the decryption engine in "automatic" mode
            CryptoPP::FileSource(inf, true, decryptor);

            inf.close(); // to be nice
        }
        catch(CryptoPP::Exception &e)
        {
            qDebug() << "Caught exception during decryption!\n";
            return false;
        }

        return true;
    }

    static void GenerateRSAKey(const char *privFilename, const char *pubFilename, const char *password)
    {
        RandomPool randPool;
        randPool.IncorporateEntropy((byte *)password, strlen(password));

        RSAES_OAEP_SHA_Decryptor priv(randPool, KEY_LENGTH);
        HexEncoder privFile(new FileSink(privFilename));
        priv.DEREncode(privFile);
        privFile.MessageEnd();

        RSAES_OAEP_SHA_Encryptor pub(priv);
        HexEncoder pubFile(new FileSink(pubFilename));
        pub.DEREncode(pubFile);
        pubFile.MessageEnd();

        return;
    }

    static string RSAEncryptString(const char *pubFilename, const char *seed, const char *message)
    {
        RandomPool randPool;
        randPool.IncorporateEntropy((byte *)seed, strlen(seed));

        FileSource pubFile(pubFilename, true, new HexDecoder);
        RSAES_OAEP_SHA_Encryptor pub(pubFile);

        string result;
        StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
        return result;
    }

    static string RSADecryptString(const char *privFilename, const char *ciphertext)
    {
        FileSource privFile(privFilename, true, new HexDecoder);
        RSAES_OAEP_SHA_Decryptor priv(privFile);

        string result;
        StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
        return result;
    }

    static void RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename)
    {
        FileSource privFile(privFilename, true, new HexDecoder);
        RSASS<PKCS1v15, SHA>::Signer priv(privFile);
        FileSource f(messageFilename, true, new SignerFilter(GlobalRNG(), priv, new HexEncoder(new FileSink(signatureFilename))));
    }

    static bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename)
    {
        FileSource pubFile(pubFilename, true, new HexDecoder);
        RSASS<PKCS1v15, SHA>::Verifier pub(pubFile);

        FileSource signatureFile(signatureFilename, true, new HexDecoder);
        if (signatureFile.MaxRetrievable() != pub.SignatureLength())
            return false;
        SecByteBlock signature(pub.SignatureLength());
        signatureFile.Get(signature, signature.size());

        VerifierFilter *verifierFilter = new VerifierFilter(pub);
        verifierFilter->Put(signature, pub.SignatureLength());
        FileSource f(messageFilename, true, verifierFilter);

        return verifierFilter->GetLastResult();
    }

    static QString GetDefaultKey()
    {
        return DEFAULT_KEY_MASK;
    }
};

ADNCryptor::ADNCryptor()
{
    _cryptor = new ADNCryptorPrivate();
}

ADNCryptor::ADNCryptor(QString encryptedFile, QString decryptedFile, CryptType type, QString key)
{
    _cryptor = new ADNCryptorPrivate(encryptedFile,decryptedFile,type,key);
}

ADNCryptor::~ADNCryptor()
{
    FREE_MEMORY(_cryptor);
}

bool ADNCryptor::Encrypt()
{
    return _cryptor->Encrypt();
}

bool ADNCryptor::Decrypt()
{
    return _cryptor->Decrypt();
}

quint64 ADNCryptor::TotalBytes()
{
    return _cryptor->bytesTotal;
}

quint64 ADNCryptor::ProcessedBytes()
{
    return _cryptor->bytesProccessed;
}

QString ADNCryptor::key() const
{
    return _cryptor->key();
}

void ADNCryptor::GenerateRSAKey(const char *privFilename, const char *pubFilename, const char *password)
{
    return ADNCryptorPrivate::GenerateRSAKey(privFilename,pubFilename,password);
}

std::string ADNCryptor::RSAEncryptString(const char *pubFilename, const char *password, const char *string)
{
    return ADNCryptorPrivate::RSAEncryptString(pubFilename,password,string);
}

std::string ADNCryptor::RSADecryptString(const char *privFilename, const char *string)
{
    return ADNCryptorPrivate::RSADecryptString(privFilename,string);
}

void ADNCryptor::RSASignFile(const char *privFilename, const char *Filename, const char *signatureFilename)
{
    return ADNCryptorPrivate::RSASignFile(privFilename,Filename,signatureFilename);
}

bool ADNCryptor::RSAVerifyFile(const char *pubFilename, const char *Filename, const char *signatureFilename)
{
    return ADNCryptorPrivate::RSAVerifyFile(pubFilename,Filename,signatureFilename);
}

QString ADNCryptor::GetDefaultKey()
{
    return ADNCryptorPrivate::GetDefaultKey();
}


