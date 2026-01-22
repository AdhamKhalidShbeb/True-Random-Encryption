#include "Backend.hpp"
#include "../core/CryptoCore.hpp"
#include "../entropy/EntropyManager.hpp"
#include "compression/CompressionManager.hpp"
#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QRandomGenerator>
#include <QThread>
#include <QUrl>
#include <QtConcurrent/QtConcurrent>
#include <cmath>
#include <fstream>

using namespace TRE;

Backend::Backend(QObject *parent)
    : QObject(parent), m_passwordStrength(0), m_compression(0),
      m_verbose(false), m_secureDelete(false), m_isEncrypting(false),
      m_progress(0.0), m_telemetryQueue(0), m_cancelRequested(false),
      m_hasMinLength(false), m_hasUppercase(false), m_hasLowercase(false),
      m_hasDigit(false), m_hasSymbol(false), m_entropyActive(true) {
  m_telemetryEntropy = "7.98 bits";
  m_telemetryThroughput = "0.00 Mbps";
  m_passwordFeedback = "Password stays on your device.";

  // Update entropy quality every second
  m_telemetryTimer = new QTimer(this);
  connect(m_telemetryTimer, &QTimer::timeout, this, [this]() {
    size_t sampleSize = 4096;
    auto buffer = EntropyManager::get_instance().get_bytes(sampleSize);

    if (buffer.empty()) {
      m_telemetryEntropy = "Unavailable";
      if (m_entropyActive) {
        m_entropyActive = false;
        emit entropyStatusChanged();
      }
    } else {
      if (!m_entropyActive) {
        m_entropyActive = true;
        emit entropyStatusChanged();
      }

      // Shannon entropy calculation
      int counts[256] = {0};
      for (unsigned char byte : buffer)
        counts[byte]++;

      double entropy = 0.0;
      for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
          double p = static_cast<double>(counts[i]) / sampleSize;
          entropy -= p * std::log2(p);
        }
      }
      m_telemetryEntropy = QString::number(entropy, 'f', 2) + " bits";
    }
    emit telemetryChanged();
  });
  m_telemetryTimer->start(1000);
  setStatus("READY");
}

QStringList Backend::files() const { return m_files; }
QString Backend::password() const { return m_password; }

void Backend::setPassword(const QString &password) {
  if (m_password != password) {
    m_password = password;
    emit passwordChanged();
    updatePasswordStrength();
  }
}

int Backend::passwordStrength() const { return m_passwordStrength; }
int Backend::compression() const { return m_compression; }

void Backend::setCompression(int level) {
  if (m_compression != level) {
    m_compression = level;
    emit compressionChanged();
  }
}

bool Backend::verbose() const { return m_verbose; }

void Backend::setVerbose(bool verbose) {
  if (m_verbose != verbose) {
    m_verbose = verbose;
    emit verboseChanged();
  }
}

bool Backend::secureDelete() const { return m_secureDelete; }

void Backend::setSecureDelete(bool secureDelete) {
  if (m_secureDelete != secureDelete) {
    m_secureDelete = secureDelete;
    emit secureDeleteChanged();
  }
}

bool Backend::isEncrypting() const { return m_isEncrypting; }
double Backend::progress() const { return m_progress; }
QString Backend::passwordFeedback() const { return m_passwordFeedback; }
QString Backend::statusMessage() const { return m_statusMessage; }
QString Backend::telemetryEntropy() const { return m_telemetryEntropy; }
QString Backend::telemetryThroughput() const { return m_telemetryThroughput; }
int Backend::telemetryQueue() const { return m_telemetryQueue; }
bool Backend::hasMinLength() const { return m_hasMinLength; }
bool Backend::hasUppercase() const { return m_hasUppercase; }
bool Backend::hasLowercase() const { return m_hasLowercase; }
bool Backend::hasDigit() const { return m_hasDigit; }
bool Backend::hasSymbol() const { return m_hasSymbol; }
bool Backend::entropyActive() const { return m_entropyActive; }

void Backend::addFiles(const QList<QUrl> &urls) {
  for (const QUrl &url : urls) {
    QString path = url.toLocalFile();
    if (!m_files.contains(path) && QFileInfo(path).exists()) {
      m_files.append(path);
    }
  }
  m_telemetryQueue = m_files.size();
  emit filesChanged();
  emit telemetryChanged();
}

void Backend::removeFile(int index) {
  if (index >= 0 && index < m_files.size()) {
    m_files.removeAt(index);
    m_telemetryQueue = m_files.size();
    emit filesChanged();
    emit telemetryChanged();
  }
}

void Backend::clearFiles() {
  m_files.clear();
  m_telemetryQueue = 0;
  emit filesChanged();
  emit telemetryChanged();
}

void Backend::encrypt() {
  if (m_files.isEmpty()) {
    setStatus("No files selected", true);
    return;
  }
  if (m_password.isEmpty()) {
    setStatus("Password needed", true);
    return;
  }

  std::string error_msg;
  if (!validate_password(m_password.toStdString(), error_msg)) {
    setStatus(QString::fromStdString(error_msg), true);
    return;
  }

  processFiles(true);
}

void Backend::decrypt() {
  if (m_files.isEmpty()) {
    setStatus("No files selected", true);
    return;
  }
  if (m_password.isEmpty()) {
    setStatus("Password needed", true);
    return;
  }

  processFiles(false);
}

void Backend::cancel() {
  QMutexLocker locker(&m_mutex);
  m_cancelRequested = true;
}

void Backend::updatePasswordStrength() {
  if (m_password.isEmpty()) {
    m_passwordStrength = 0;
    m_passwordFeedback = "Password stays on your device.";
    m_hasMinLength = m_hasUppercase = m_hasLowercase = m_hasDigit =
        m_hasSymbol = false;
  } else {
    int score = 0;
    qsizetype len = m_password.length();

    if (len >= 8)
      score += 10;
    if (len >= 12)
      score += 15;
    if (len >= 16)
      score += 25;
    if (len >= 20)
      score += 10;

    int upperCount = 0, lowerCount = 0, digitCount = 0, symbolCount = 0;
    for (const QChar &c : m_password) {
      if (c.isUpper())
        upperCount++;
      else if (c.isLower())
        lowerCount++;
      else if (c.isDigit())
        digitCount++;
      else
        symbolCount++;
    }

    if (upperCount > 0)
      score += 10;
    if (lowerCount > 0)
      score += 10;
    if (digitCount > 0)
      score += 10;
    if (symbolCount > 0)
      score += 10;
    if (upperCount >= 2)
      score += 5;
    if (lowerCount >= 2)
      score += 5;
    if (digitCount >= 2)
      score += 5;
    if (symbolCount >= 2)
      score += 5;

    std::string error_msg;
    if (!validate_password(m_password.toStdString(), error_msg)) {
      score = qMin(score, 80);
    }
    m_passwordStrength = qMin(score, 100);

    QStringList missing;
    if (len < 16)
      missing << "more length";
    if (upperCount < 2)
      missing << "uppercase";
    if (lowerCount < 2)
      missing << "lowercase";
    if (digitCount < 2)
      missing << "digits";
    if (symbolCount < 2)
      missing << "symbols";

    if (missing.isEmpty()) {
      m_passwordFeedback = "Strong password. Ready to go.";
    } else {
      m_passwordFeedback = QString("%1% - needs %2")
                               .arg(m_passwordStrength)
                               .arg(missing.join(", "));
    }

    m_hasMinLength = (len >= 16);
    m_hasUppercase = (upperCount >= 2);
    m_hasLowercase = (lowerCount >= 2);
    m_hasDigit = (digitCount >= 2);
    m_hasSymbol = (symbolCount >= 2);
  }
  emit passwordStrengthChanged();
  emit passwordFeedbackChanged();
  emit passwordRequirementsChanged();
}

void Backend::setStatus(const QString &message, bool) {
  m_statusMessage = message;
  emit statusMessageChanged();
}

void Backend::setProgress(double value) {
  m_progress = value;
  emit progressChanged();
}

void Backend::processFiles(bool encrypt) {
  m_isEncrypting = true;
  emit isEncryptingChanged();
  m_cancelRequested = false;
  setProgress(0.0);

  QtConcurrent::run([this, encrypt]() {
    int total = m_files.size();
    int success = 0;
    int failed = 0;
    qint64 totalBytesProcessed = 0;
    QElapsedTimer timer;
    timer.start();

    QMetaObject::invokeMethod(this, [this, total]() {
      m_telemetryQueue = total;
      m_telemetryThroughput = "0.00 Mbps";
      emit telemetryChanged();
    });

    QString password = m_password;
    int compressionLevel = m_compression;
    bool verbose = m_verbose;
    bool secureDel = m_secureDelete;

    for (int i = 0; i < total; i++) {
      {
        QMutexLocker locker(&m_mutex);
        if (m_cancelRequested)
          break;
      }

      QString path = m_files[i];
      QString name = QFileInfo(path).fileName();
      qint64 fileSize = QFileInfo(path).size();

      QMetaObject::invokeMethod(this, [this, i, total, name, encrypt]() {
        setStatus(QString("%1 %2/%3: %4")
                      .arg(encrypt ? "Encrypting" : "Decrypting")
                      .arg(i + 1)
                      .arg(total)
                      .arg(name));
        setProgress(double(i) / total);
      });

      try {
        std::string input_path = path.toStdString();
        std::string pass_str = password.toStdString();
        double currentEntropy = 0.0;

        if (encrypt) {
          std::string output_path =
              auto_generate_output_filename(input_path, "encrypt");

          std::ifstream infile(input_path, std::ios::binary);
          if (!infile)
            throw std::runtime_error("Can't open file");

          auto salt = EntropyManager::get_instance().get_bytes(SALT_SIZE);

          // Measure salt entropy
          int counts[256] = {0};
          for (unsigned char b : salt)
            counts[b]++;
          for (int k = 0; k < 256; ++k) {
            if (counts[k] > 0) {
              double p = static_cast<double>(counts[k]) / salt.size();
              currentEntropy -= p * std::log2(p);
            }
          }

          auto key = derive_key(pass_str.c_str(), pass_str.size(), salt);
          auto nonce = EntropyManager::get_instance().get_bytes(NONCE_SIZE);
          secure_wipe_string(pass_str);

          std::vector<unsigned char> plaintext(
              (std::istreambuf_iterator<char>(infile)),
              std::istreambuf_iterator<char>());
          infile.close();

          if (compressionLevel > 0) {
            plaintext = compress_data(
                plaintext, static_cast<CompressionLevel>(compressionLevel),
                verbose);
          }

          auto ciphertext = encrypt_aes256gcm(plaintext, key, nonce);
          secure_wipe_vector(plaintext);
          secure_wipe_vector(key);

          std::string ext = extract_extension(input_path);
          unsigned char ext_len = static_cast<unsigned char>(ext.length());

          std::ofstream outfile(output_path, std::ios::binary);
          if (!outfile)
            throw std::runtime_error("Can't write file");

          outfile.write(reinterpret_cast<const char *>(&FILE_FORMAT_VERSION),
                        1);
          outfile.write(reinterpret_cast<const char *>(&ext_len), 1);
          if (ext_len > 0)
            outfile.write(ext.c_str(), ext_len);
          outfile.write(reinterpret_cast<const char *>(salt.data()), SALT_SIZE);
          outfile.write(reinterpret_cast<const char *>(nonce.data()),
                        NONCE_SIZE);
          unsigned char comp_byte =
              static_cast<unsigned char>(compressionLevel);
          outfile.write(reinterpret_cast<const char *>(&comp_byte), 1);
          outfile.write(reinterpret_cast<const char *>(ciphertext.data()),
                        ciphertext.size());
          outfile.close();

          if (secureDel)
            secure_delete_file(input_path);

        } else {
          std::string output_path =
              auto_generate_output_filename(input_path, "decrypt");

          std::ifstream infile(input_path, std::ios::binary);
          if (!infile)
            throw std::runtime_error("Can't open file");

          unsigned char version;
          infile.read(reinterpret_cast<char *>(&version), 1);
          if (version != FILE_FORMAT_VERSION)
            throw std::runtime_error("Bad file format");

          unsigned char ext_len;
          infile.read(reinterpret_cast<char *>(&ext_len), 1);
          if (ext_len >= 32)
            throw std::runtime_error("Bad extension");

          std::string stored_ext;
          if (ext_len > 0) {
            stored_ext.resize(ext_len);
            infile.read(&stored_ext[0], ext_len);
          }

          std::vector<unsigned char> salt(SALT_SIZE);
          infile.read(reinterpret_cast<char *>(salt.data()), SALT_SIZE);

          int counts[256] = {0};
          for (unsigned char b : salt)
            counts[b]++;
          for (int k = 0; k < 256; ++k) {
            if (counts[k] > 0) {
              double p = static_cast<double>(counts[k]) / salt.size();
              currentEntropy -= p * std::log2(p);
            }
          }

          std::vector<unsigned char> nonce(NONCE_SIZE);
          infile.read(reinterpret_cast<char *>(nonce.data()), NONCE_SIZE);

          unsigned char comp_byte;
          infile.read(reinterpret_cast<char *>(&comp_byte), 1);
          CompressionLevel comp_level =
              static_cast<CompressionLevel>(comp_byte);

          std::vector<unsigned char> ciphertext(
              (std::istreambuf_iterator<char>(infile)),
              std::istreambuf_iterator<char>());
          infile.close();

          auto key = derive_key(pass_str.c_str(), pass_str.size(), salt);
          secure_wipe_string(pass_str);

          auto plaintext = decrypt_aes256gcm(ciphertext, key, nonce);
          secure_wipe_vector(key);

          if (comp_level != CompressionLevel::NONE) {
            plaintext = decompress_data(plaintext, verbose);
          }

          std::ofstream outfile(output_path, std::ios::binary);
          if (!outfile)
            throw std::runtime_error("Can't write file");
          outfile.write(reinterpret_cast<const char *>(plaintext.data()),
                        plaintext.size());
          outfile.close();
          secure_wipe_vector(plaintext);
        }

        success++;
        totalBytesProcessed += fileSize;

        double elapsedSec = timer.elapsed() / 1000.0;
        double mbps =
            (elapsedSec > 0)
                ? (totalBytesProcessed * 8.0 / (1024.0 * 1024.0 * elapsedSec))
                : 0.0;
        double entropy = currentEntropy;

        QMetaObject::invokeMethod(this, [this, mbps, entropy, total, i]() {
          m_telemetryThroughput = QString::number(mbps, 'f', 2) + " Mbps";
          m_telemetryEntropy = QString::number(entropy, 'f', 2) + " bits";
          m_telemetryQueue = total - (i + 1);
          emit telemetryChanged();
        });

      } catch (const std::exception &e) {
        failed++;
        QMetaObject::invokeMethod(this, [this, e]() {
          setStatus(QString("Failed: %1").arg(e.what()), true);
        });
      }
    }

    QMetaObject::invokeMethod(this, [this, success, total, failed, encrypt]() {
      m_isEncrypting = false;
      emit isEncryptingChanged();
      setProgress(1.0);
      QString result = QString("%1 %2/%3")
                           .arg(encrypt ? "Encrypted" : "Decrypted")
                           .arg(success)
                           .arg(total);
      if (failed > 0)
        result += QString(" (%1 failed)").arg(failed);
      setStatus(result, failed > 0);
    });
  });
}
