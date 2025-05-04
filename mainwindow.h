#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {class MainWindow;}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onEncrypt(); // slot do obslugi wykonania operacji

private:
    Ui::MainWindow *ui;

    void initializeRandom();

    QString encryptCaesar(const QString &message, int key);
    QString encryptVigenere(const QString &message, const QString &key);
    QString encryptAES(QString &message, QString &key);
    QString encryptDES(QString &message, QString &key);
    QString encryptRSA(const QString &message, QString &key);
    void generateRSAKeys();
    QString encryptXOR(const QString &message, const QString &key);
    QString encryptBase64(const QString &message);
    QString encryptSHA(const QString &message);
    QString encryptMD5(const QString &message);
    // QString encryptidk(QString &message, QString &key);

    QString decryptCaesar(const QString &message, int &key);
    QString decryptVigenere(const QString &message, const QString &key);
    QString decryptAES(QString &message, QString &key);
    QString decryptDES(QString &message, QString &key);
    QString decryptRSA(const QString &message, const QString &key);
    QString decryptXOR(const QString &message, const QString &key);
    QString decryptBase64(QString &message);
    QString decryptSHA(const QString& text, const QString& key);
    QString decryptMD5(const QString& text, const QString& key);


    //Tu powyżej będziemy dodawać kolejne funkcje szyfrujące
};
#endif // MAINWINDOW_H
