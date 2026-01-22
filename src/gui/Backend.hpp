#ifndef BACKEND_HPP
#define BACKEND_HPP

#include <QMutex>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QUrl>
#include <QVector>

// Bridges the QML UI to the crypto backend
class Backend : public QObject {
  Q_OBJECT

  // File list
  Q_PROPERTY(QStringList files READ files NOTIFY filesChanged)

  // Password
  Q_PROPERTY(
      QString password READ password WRITE setPassword NOTIFY passwordChanged)
  Q_PROPERTY(
      int passwordStrength READ passwordStrength NOTIFY passwordStrengthChanged)
  Q_PROPERTY(QString passwordFeedback READ passwordFeedback NOTIFY
                 passwordFeedbackChanged)

  // Password requirement checks
  Q_PROPERTY(
      bool hasMinLength READ hasMinLength NOTIFY passwordRequirementsChanged)
  Q_PROPERTY(
      bool hasUppercase READ hasUppercase NOTIFY passwordRequirementsChanged)
  Q_PROPERTY(
      bool hasLowercase READ hasLowercase NOTIFY passwordRequirementsChanged)
  Q_PROPERTY(bool hasDigit READ hasDigit NOTIFY passwordRequirementsChanged)
  Q_PROPERTY(bool hasSymbol READ hasSymbol NOTIFY passwordRequirementsChanged)

  // Options
  Q_PROPERTY(int compression READ compression WRITE setCompression NOTIFY
                 compressionChanged)
  Q_PROPERTY(bool verbose READ verbose WRITE setVerbose NOTIFY verboseChanged)
  Q_PROPERTY(bool secureDelete READ secureDelete WRITE setSecureDelete NOTIFY
                 secureDeleteChanged)

  // Status
  Q_PROPERTY(bool isEncrypting READ isEncrypting NOTIFY isEncryptingChanged)
  Q_PROPERTY(double progress READ progress NOTIFY progressChanged)
  Q_PROPERTY(
      QString statusMessage READ statusMessage NOTIFY statusMessageChanged)

  // Telemetry
  Q_PROPERTY(
      QString telemetryEntropy READ telemetryEntropy NOTIFY telemetryChanged)
  Q_PROPERTY(QString telemetryThroughput READ telemetryThroughput NOTIFY
                 telemetryChanged)
  Q_PROPERTY(int telemetryQueue READ telemetryQueue NOTIFY telemetryChanged)
  Q_PROPERTY(bool entropyActive READ entropyActive NOTIFY entropyStatusChanged)

public:
  explicit Backend(QObject *parent = nullptr);

  QStringList files() const;
  QString password() const;
  void setPassword(const QString &password);
  int passwordStrength() const;
  QString passwordFeedback() const;
  int compression() const;
  void setCompression(int level);
  bool verbose() const;
  void setVerbose(bool verbose);
  bool secureDelete() const;
  void setSecureDelete(bool secureDelete);
  bool isEncrypting() const;
  double progress() const;
  QString statusMessage() const;
  QString telemetryEntropy() const;
  QString telemetryThroughput() const;
  int telemetryQueue() const;
  bool hasMinLength() const;
  bool hasUppercase() const;
  bool hasLowercase() const;
  bool hasDigit() const;
  bool hasSymbol() const;
  bool entropyActive() const;

  Q_INVOKABLE void addFiles(const QList<QUrl> &urls);
  Q_INVOKABLE void removeFile(int index);
  Q_INVOKABLE void clearFiles();
  Q_INVOKABLE void encrypt();
  Q_INVOKABLE void decrypt();
  Q_INVOKABLE void cancel();

signals:
  void filesChanged();
  void passwordChanged();
  void passwordStrengthChanged();
  void passwordFeedbackChanged();
  void compressionChanged();
  void verboseChanged();
  void secureDeleteChanged();
  void isEncryptingChanged();
  void progressChanged();
  void statusMessageChanged();
  void telemetryChanged();
  void passwordRequirementsChanged();
  void entropyStatusChanged();

private:
  void updatePasswordStrength();
  void processFiles(bool encrypt);
  void setStatus(const QString &message, bool isError = false);
  void setProgress(double value);

  QStringList m_files;
  QString m_password;
  int m_passwordStrength;
  QString m_passwordFeedback;
  int m_compression;
  bool m_verbose;
  bool m_secureDelete;
  bool m_isEncrypting;
  double m_progress;
  QString m_statusMessage;

  QString m_telemetryEntropy;
  QString m_telemetryThroughput;
  int m_telemetryQueue;
  bool m_hasMinLength;
  bool m_hasUppercase;
  bool m_hasLowercase;
  bool m_hasDigit;
  bool m_hasSymbol;
  bool m_entropyActive;

  QTimer *m_telemetryTimer;
  bool m_cancelRequested;
  QMutex m_mutex;
};

#endif
