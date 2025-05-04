#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QMessageBox>
#include <QByteArray>
#include <QString>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <QCryptographicHash>


#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

     // Inicjalizacja OpenSSL, jest to opcjonalne zabezpieczenie przed występującymi błędami
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_all_ciphers();


    initializeRandom();

    // Podłącz przycisk do slotu, aby mógł wywołać funkcję onEncrypt
    connect(ui->pushButton, &QPushButton::clicked, this, &MainWindow::onEncrypt);
}

MainWindow::~MainWindow()
{
    delete ui;
}

// Slot obsługujący przycisk wykonania
void MainWindow::onEncrypt()
{
    QString message = ui->textEdit->toPlainText();   // Pobranie wiadomości
    QString key = ui->textEdit_3->toPlainText();     // Pobranie klucza
    QString result;

    // to rozszerzenie na ewentualne kolejne algorytmy asymetryczne
    // QString publicKey, privateKey;

    // tu się aktywuje funkcje zależnie od zaznaczonego radioButtona

    if (ui->radioButton->isChecked()) {
        int keyValue = key.toInt();
        result = encryptCaesar(message, keyValue);
    }
    if (ui->radioButton_2->isChecked()) {
        result = encryptVigenere(message, key);
    }
    if (ui->radioButton_3->isChecked()) {
        result = encryptAES(message, key);
    }
    if (ui->radioButton_4->isChecked()) {
        result = encryptDES(message, key);
    }
    if (ui->radioButton_5->isChecked()) {
        result = encryptRSA(message, key);
    }
    if (ui->radioButton_6->isChecked()) {
        result = encryptXOR(message, key);
    }
    if (ui->radioButton_7->isChecked()) {
        result = encryptBase64(message);
    }
    if (ui->radioButton_8->isChecked()) {
        result = encryptSHA(message);
    }
    if (ui->radioButton_9->isChecked()) {
        result = encryptMD5(message);
    }
    if (ui->radioButton_10->isChecked()) {
        result = "uj pije piwo z popita";
    }

    // zadanie dla Oskara

     if (ui -> radioButton_11 -> isChecked()) {
         int keyValue = key.toInt();
         result = decryptCaesar(message, keyValue);
     }
     if (ui -> radioButton_12 -> isChecked()) {
         result = decryptVigenere(message, key);
     }
     if (ui -> radioButton_13 -> isChecked()) {
         result = decryptAES(message, key);
     }
     if (ui -> radioButton_14 -> isChecked()) {
         result = decryptDES(message, key);
     }
     if (ui -> radioButton_15 -> isChecked()) {
         result = decryptRSA(message, key);
     }
     if (ui -> radioButton_16 -> isChecked()) {
         result = decryptXOR(message, key);
     }
     if (ui -> radioButton_17 -> isChecked()) {
         result = decryptBase64(message);
     }
     if (ui -> radioButton_18 -> isChecked()) {
         result = decryptSHA(message, key);
     }
     if (ui -> radioButton_19 -> isChecked()) {
         result = decryptMD5(message, key);
     }

    if (ui -> radioButton_20 -> isChecked()) {
        generateRSAKeys();
    }

    // Dodaj obsługę innych szyfrów tutaj (raczej już skończone)

    ui->textEdit_2->setText(result); // Wyświetlenie szyfrogramu
}

// to jest ważna funcja sprawdzająca czy klucze aby na pewno generują się losowo

void MainWindow::initializeRandom() {
    if (!RAND_load_file("/dev/urandom", 1024)) {
        QMessageBox::warning(this, "Błąd", "Nie udało się zainicjować generatora liczb losowych!");
    }
}


QString MainWindow::encryptCaesar(const QString &message, int key) {
    QString result;
    for (const QChar &ch : message) {
        if (ch.isLetter()) {
            QChar base = ch.isLower() ? 'a' : 'A';
            result.append(QChar((ch.unicode() - base.unicode() + key) % 26 + base.unicode()));
        } else {
            result.append(ch); // Pozostaw inne znaki bez zmian
        }
    }
    return result;
}


QString MainWindow::encryptVigenere(const QString &message, const QString &key) {
    QString result = message;
    int keyIndex = 0;
    for (QChar &c : result) {
        if (c.isLetter()) {
            QChar base = c.isLower() ? QLatin1Char('a') : QLatin1Char('A');
            int shift = key[keyIndex % key.size()].toLower().unicode() - QLatin1Char('a').unicode();
            c = QChar((c.unicode() - base.unicode() + shift) % 26 + base.unicode());
            keyIndex++;
        }
    }
    return result;
}


QString MainWindow::encryptAES(QString &message, QString &key) {
    // Sprawdzamy, czy długość klucza wynosi dokładnie 32 znaki (256 bitów dla AES-256)
    if (key.length() != 32) {
        QMessageBox::warning(this, "Error", "The key for AES must be 32 characters long!");
        return "";
    }

    QString result;


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Tworzymy nowy kontekst do szyfrowania
    unsigned char iv[EVP_MAX_IV_LENGTH] = {};  // Inicjalizujemy wektor IV zerami, ponieważ jego długość musi być zgodna z algorytmem
    // tu się przygotowuje bufor na zaszyfrowane dane. Rozmiar bufora to długość wiadomości + max rozmiar bloku szyfrującego
    unsigned char *ciphertext = new unsigned char[message.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int len, ciphertext_len;

    // inicjalizujemy kontekst szyfrowania
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       reinterpret_cast<const unsigned char *>(key.toStdString().c_str()), iv);

    // aktualizujemy szyfrowanie - przetwarzanie głównej części wiadomości
    EVP_EncryptUpdate(ctx, ciphertext, &len,
                     reinterpret_cast<const unsigned char *>(message.toStdString().c_str()), message.size());

    ciphertext_len = len;

    // finalizacja szyfrowania - przetwarzanie pozostałych danych (padding)
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    // czyszczenie używanego kontekstu
    EVP_CIPHER_CTX_free(ctx);

    // szyfrogram konwertujemy na QByteArray aby można było je zakodować w Base64
    QByteArray encryptedData(reinterpret_cast<char *>(ciphertext), ciphertext_len);
    result = encryptedData.toBase64(); // Kodowanie Base64 (bardziej czytelny)
    delete[] ciphertext;

    return result;
}


QString MainWindow::encryptDES(QString &message, QString &key) {
    if (key.length() != 8) {
        QMessageBox::warning(this, "Błąd", "The key for DES must be 8 characters long!");
        return "";
    }

    // Przygotowanie klucza DES
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    QByteArray keyBytes = key.toLatin1();
    memcpy(keyBlock, keyBytes.data(), 8);

    DES_set_odd_parity(&keyBlock);

    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        QMessageBox::warning(this, "Błąd", "Invalid DES key provided.");
        return "";
    }

    // Paddowanie wiadomości
    QByteArray inputBytes = message.toLatin1();
    size_t paddingSize = 8 - (inputBytes.size() % 8);
    inputBytes.append(paddingSize, static_cast<char>(paddingSize));

    // Wynik szyfrowania
    std::vector<unsigned char> output(inputBytes.size());

    // Szyfrowanie blok po bloku
    for (size_t i = 0; i < inputBytes.size(); i += 8) {
        DES_ecb_encrypt(
            reinterpret_cast<const_DES_cblock*>(inputBytes.data() + i),
            reinterpret_cast<DES_cblock*>(output.data() + i),
            &schedule,
            DES_ENCRYPT);
    }

    // Konwersja wyniku na QString
    QByteArray encryptedData(reinterpret_cast<char*>(output.data()), output.size());
    return QString::fromLatin1(encryptedData.toHex());
}


QString MainWindow::encryptRSA(const QString &message, QString &key) {
    QByteArray messageBytes = message.toUtf8();
    QByteArray keyBytes = key.toUtf8().trimmed();

    //tworzenie struktury klucza publicznego z łańcucha
    BIO *bio = BIO_new_mem_buf(keyBytes.constData(), keyBytes.length());

    if (bio == nullptr) {
        QMessageBox::warning(this, "Błąd", "Nie udało się utworzyć BIO z klucza!");
        return "";
    }

    BIO *errBio = BIO_new(BIO_s_mem());

    RSA *rsaPublicKey = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if(!rsaPublicKey) {
        ERR_print_errors(errBio);
        // Wyciągnięcie błędów z obiektu BIO do QString
        char *errBuff;
        long errLen = BIO_get_mem_data(errBio, &errBuff);
        QString errMsg = QString::fromUtf8(errBuff, errLen);

        QMessageBox::warning(this, "Błąd", "The program failed to load the key! Błędy OpenSSL: " + errMsg);

        BIO_free_all(bio);
        BIO_free_all(errBio);
        return "";
    }

    // mięsko i ziemniaczki algorytmu
    std::vector<unsigned char> encryptedData(RSA_size(rsaPublicKey));
    int result = RSA_public_encrypt(
        messageBytes.size(),
        reinterpret_cast<const unsigned char *>(messageBytes.data()),
        encryptedData.data(),
        rsaPublicKey,
        RSA_PKCS1_PADDING);

    RSA_free(rsaPublicKey);

    if (result == -1) {
        QMessageBox::warning(this, "Błąd", QString("Błąd szyfrowania RSA: %1").arg(ERR_error_string(ERR_get_error(), nullptr)));
        return "";
    }

    // konwersja danych aby były jakkkolwiek czytelne
    QByteArray encryptedBase64 = QByteArray(reinterpret_cast<const char *>(encryptedData.data()), result).toBase64();
    return QString::fromUtf8(encryptedBase64);
}

void MainWindow::generateRSAKeys() {
    int keyLength = 2048;
    RSA *rsa = RSA_generate_key(keyLength, RSA_F4, nullptr, nullptr);
    BIO *pubBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(pubBio, rsa);
    BIO *priBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priBio, rsa, nullptr, nullptr, 0, nullptr, nullptr);

    char *pubKeyChar;
    long pubKeyLen = BIO_get_mem_data(pubBio, &pubKeyChar);
    QString publicKey = QString::fromUtf8(pubKeyChar, pubKeyLen);

    char *priKeyChar;
    long priKeyLen = BIO_get_mem_data(priBio, &priKeyChar);
    QString privateKey = QString::fromUtf8(priKeyChar, priKeyLen);

    BIO_free_all(pubBio);
    BIO_free_all(priBio);
    RSA_free(rsa);

    QMessageBox::information(this, "Wygenerowane klucze RSA",
            "Klucz publiczny:\n" + publicKey + "\n\nKlucz prywatny: \n" + privateKey);
}
QString MainWindow::encryptXOR(const QString &message, const QString &key) {
    if (key.length() == 0) {
        QMessageBox::warning(this, "Błąd", "Invalid XOR key provided");
        return "";
    }

    QString result;
    for (int i = 0; i < message.size(); ++i) {
        result += QChar(uchar(message[i].unicode()) ^ uchar(key[i % key.size()].unicode()));
    }
    return result;
}


QString MainWindow::encryptBase64(const QString &message) {
    QString result;
    const QString base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, valb = -6;
    for (QChar qc : message) {
        unsigned char c = qc.toLatin1();
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (result.size() % 4) result.push_back('=');
    return result;
}


QString MainWindow::encryptSHA(const QString &message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    QByteArray byteArray = message.toLatin1();
    const char* str = byteArray.data();

    SHA256_CTX sha256; SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, byteArray.size());
    SHA256_Final(hash, &sha256); QString result;

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        result.append(QString::number(hash[i], 16).rightJustified(2, '0'));
    }

    return result;
}


QString MainWindow::encryptMD5(const QString &message) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    QByteArray byteArray = message.toLatin1();
    const char* str = byteArray.data();

    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, str, byteArray.size());
    MD5_Final(hash, &md5);

    QString result;

        for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            result.append(QString::number(hash[i], 16).rightJustified(2, '0'));
        }

    return result;
}
QString MainWindow::decryptCaesar(const QString &message, int &key) {
    QString decryptedMessage;
    for (QChar ch : message) {
        if (ch.isLetter()) {
            QChar base = ch.isUpper() ? 'A' : 'a';
            decryptedMessage.append(QChar((ch.unicode() - base.unicode() - key + 26) % 26 + base.unicode()));
        } else {
            decryptedMessage.append(ch);
        }
    }
    return decryptedMessage;
}

QString MainWindow::decryptVigenere(const QString &message, const QString &key) {
    QString decryptedMessage;
    int keyLength = key.length();
    for (int i = 0; i < message.length(); i++) {
        QChar ch = message[i];
        if (ch.isLetter()) {
            QChar base = ch.isUpper() ? 'A' : 'a';
            int keyShift = key[i % keyLength].unicode() - base.unicode();
            decryptedMessage.append(QChar((ch.unicode() - base.unicode() - keyShift + 26) % 26 + base.unicode()));
        } else {
            decryptedMessage.append(ch);
        }
    }
    return decryptedMessage;
}

QString MainWindow::decryptAES(QString &ciphertext, QString &key) {
    if (key.length() != 32) {
        QMessageBox::warning(this, "Error", "The key for AES must be 32 characters long!");
        return "";
    }

    QByteArray encryptedData = QByteArray::fromBase64(ciphertext.toUtf8());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[EVP_MAX_IV_LENGTH] = {};

    unsigned char *plaintext = new unsigned char[encryptedData.size()];
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       reinterpret_cast<const unsigned char *>(key.toStdString().c_str()), iv);

    EVP_DecryptUpdate(ctx, plaintext, &len,
                      reinterpret_cast<const unsigned char *>(encryptedData.data()), encryptedData.size());
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    QString result = QString::fromUtf8(reinterpret_cast<char *>(plaintext), plaintext_len);
    delete[] plaintext;

    return result;
}


QString MainWindow::decryptDES(QString &message, QString &key) {
    if (key.length() != 8) {
        QMessageBox::warning(this, "Error", "The key for DES must be 8 characters long!");
        return "";
    }

    DES_cblock keyBlock;
    DES_key_schedule schedule;

    QByteArray keyBytes = key.toLatin1();
    memcpy(keyBlock, keyBytes.data(), 8);

    DES_set_odd_parity(&keyBlock);

    if (DES_set_key_checked(&keyBlock, &schedule) != 0) {
        QMessageBox::warning(this, "Error", "Invalid DES key provided.");
        return "";
    }

    QByteArray encryptedBytes = QByteArray::fromHex(message.toLatin1());

    QByteArray decryptedBytes(encryptedBytes.size(), 0);

    for (int i = 0; i < encryptedBytes.size(); i += 8) {
        DES_ecb_encrypt(
            reinterpret_cast<const_DES_cblock *>(encryptedBytes.data() + i),
            reinterpret_cast<DES_cblock *>(decryptedBytes.data() + i),
            &schedule,
            DES_DECRYPT);
    }

    char paddingSize = decryptedBytes.at(decryptedBytes.size() - 1);
    decryptedBytes.chop(paddingSize);

    return QString::fromLatin1(decryptedBytes);
}



QString MainWindow::decryptRSA(const QString &message, const QString &key) {
    QByteArray encryptedBytes = QByteArray::fromBase64(message.toUtf8());
    QByteArray keyBytes = key.toUtf8().trimmed();

    BIO *bio = BIO_new_mem_buf(keyBytes.constData(), keyBytes.length());

    if (bio == nullptr) {
        QMessageBox::warning(this, "Error", "Failed to create BIO for the private key!");
        return "";
    }

    RSA *rsaPrivateKey = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsaPrivateKey) {
        QMessageBox::warning(this, "Error", "Failed to load the private key!");
        return "";
    }

    std::vector<unsigned char> decryptedData(RSA_size(rsaPrivateKey));

    int result = RSA_private_decrypt(
        encryptedBytes.size(),
        reinterpret_cast<const unsigned char *>(encryptedBytes.data()),
        decryptedData.data(),
        rsaPrivateKey,
        RSA_PKCS1_PADDING);

    RSA_free(rsaPrivateKey);

    if (result == -1) {
        QMessageBox::warning(this, "Error", QString("RSA decryption error: %1").arg(ERR_error_string(ERR_get_error(), nullptr)));
        return "";
    }

    return QString::fromUtf8(reinterpret_cast<const char *>(decryptedData.data()), result);
}


QString MainWindow::decryptXOR(const QString &message, const QString &key) {
    if (key.isEmpty()) {
        QMessageBox::warning(this, "Error", "Invalid XOR key provided!");
        return "";
    }

    QString result;
    for (int i = 0; i < message.size(); ++i) {
        result += QChar(uchar(message[i].unicode()) ^ uchar(key[i % key.size()].unicode()));
    }
    return result;
}


QString MainWindow::decryptBase64(QString &message) {
    QByteArray byteArray = QByteArray::fromBase64(message.toUtf8());
    return QString(byteArray);
}



QString MainWindow::decryptSHA(const QString& givenHash, const QString& key) {
    QByteArray keyBytes = key.toUtf8();

    QCryptographicHash hasher(QCryptographicHash::Sha256);
    hasher.addData(keyBytes);
    QByteArray computedHash = hasher.result();
    QString computedHashHex = computedHash.toHex();

    qDebug() << "Computed SHA Hash:" << computedHashHex;
    qDebug() << "Given Hash:" << givenHash;

    if (computedHashHex == givenHash) {
        return "Hash is correct";
    } else {
        return "Hash is not correct";
    }
}

QString MainWindow::decryptMD5(const QString& givenHash, const QString& key) {
    QByteArray keyBytes = key.toUtf8();

    QCryptographicHash hasher(QCryptographicHash::Md5);
    hasher.addData(keyBytes);
    QByteArray computedHash = hasher.result();
    QString computedHashHex = computedHash.toHex();

    qDebug() << "Computed MD5 Hash:" << computedHashHex;
    qDebug() << "Given Hash:" << givenHash;

    if (computedHashHex == givenHash) {
        return "Hash is correct";
    } else {
        return "Hash is not correct";
    }
}

