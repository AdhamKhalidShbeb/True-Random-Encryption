#include "MainWindow.hpp"
#include "../core/CryptoCore.hpp"
#include "../entropy/EntropyManager.hpp"
#include "compression/CompressionManager.hpp"
#include <QApplication>
#include <QFile>
#include <QGroupBox>
#include <QStyle>
#include <fstream>

using namespace QRE;

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
  setupUi();
  applyTheme();
  setAcceptDrops(true);
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUi() {
  setWindowTitle(QStringLiteral("Quantum Random Encryption"));
  resize(600, 400);

  auto *centralWidget = new QWidget(this);
  setCentralWidget(centralWidget);

  auto *mainLayout = new QVBoxLayout(centralWidget);
  mainLayout->setSpacing(20);
  mainLayout->setContentsMargins(30, 30, 30, 30);

  // Header
  auto *titleLabel =
      new QLabel(QStringLiteral("Quantum Random Encryption"), this);
  titleLabel->setObjectName(QStringLiteral("titleLabel"));
  titleLabel->setAlignment(Qt::AlignCenter);
  mainLayout->addWidget(titleLabel);

  // Input File Area
  auto *inputGroup = new QGroupBox(QStringLiteral("Input File"), this);
  auto *inputLayout = new QVBoxLayout(inputGroup);

  auto *fileLayout = new QHBoxLayout();
  inputPathEdit_ = new QLineEdit(this);
  inputPathEdit_->setPlaceholderText(
      QStringLiteral("Drag & drop file here or browse..."));
  browseButton_ = new QPushButton(QStringLiteral("Browse"), this);
  fileLayout->addWidget(inputPathEdit_);
  fileLayout->addWidget(browseButton_);
  inputLayout->addLayout(fileLayout);
  mainLayout->addWidget(inputGroup);

  // Password Area
  auto *passwordGroup = new QGroupBox(QStringLiteral("Password"), this);
  auto *passLayout = new QVBoxLayout(passwordGroup);

  auto *passInputLayout = new QHBoxLayout();
  passwordEdit_ = new QLineEdit(this);
  passwordEdit_->setEchoMode(QLineEdit::Password);
  passwordEdit_->setPlaceholderText(QStringLiteral("Enter secure password"));

  togglePasswordButton_ = new QPushButton(QStringLiteral("👁"), this);
  togglePasswordButton_->setFixedWidth(30);
  togglePasswordButton_->setCheckable(true);

  passInputLayout->addWidget(passwordEdit_);
  passInputLayout->addWidget(togglePasswordButton_);
  passLayout->addLayout(passInputLayout);
  mainLayout->addWidget(passwordGroup);

  // Actions
  auto *actionLayout = new QHBoxLayout();
  encryptButton_ = new QPushButton(QStringLiteral("ENCRYPT"), this);
  encryptButton_->setObjectName(QStringLiteral("encryptButton"));
  encryptButton_->setMinimumHeight(50);

  decryptButton_ = new QPushButton(QStringLiteral("DECRYPT"), this);
  decryptButton_->setObjectName(QStringLiteral("decryptButton"));
  decryptButton_->setMinimumHeight(50);

  actionLayout->addWidget(encryptButton_);
  actionLayout->addWidget(decryptButton_);
  mainLayout->addLayout(actionLayout);

  // Status
  progressBar_ = new QProgressBar(this);
  progressBar_->setTextVisible(false);
  progressBar_->setRange(0, 0); // Indeterminate
  progressBar_->hide();
  mainLayout->addWidget(progressBar_);

  statusLabel_ = new QLabel(QStringLiteral("Ready"), this);
  statusLabel_->setAlignment(Qt::AlignCenter);
  mainLayout->addWidget(statusLabel_);

  // Connections
  connect(browseButton_, &QPushButton::clicked, this,
          &MainWindow::onBrowseInput);
  connect(encryptButton_, &QPushButton::clicked, this, &MainWindow::onEncrypt);
  connect(decryptButton_, &QPushButton::clicked, this, &MainWindow::onDecrypt);
  connect(togglePasswordButton_, &QPushButton::toggled, this,
          &MainWindow::onTogglePasswordVisibility);
}

void MainWindow::applyTheme() {
  QFile file(QStringLiteral(":/style.qss"));
  if (file.open(QFile::ReadOnly)) {
    qApp->setStyleSheet(QLatin1String(file.readAll()));
    return;
  }

  // Fallback: try loading from relative path
  QFile localFile(QStringLiteral("src/gui/resources/style.qss"));
  if (localFile.open(QFile::ReadOnly)) {
    qApp->setStyleSheet(QLatin1String(localFile.readAll()));
  }
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event) {
  if (event->mimeData()->hasUrls()) {
    event->acceptProposedAction();
  }
}

void MainWindow::dropEvent(QDropEvent *event) {
  if (const auto *mimeData = event->mimeData(); mimeData->hasUrls()) {
    inputPathEdit_->setText(mimeData->urls().at(0).toLocalFile());
  }
}

void MainWindow::onBrowseInput() {
  const QString fileName =
      QFileDialog::getOpenFileName(this, QStringLiteral("Select File"));
  if (!fileName.isEmpty()) {
    inputPathEdit_->setText(fileName);
  }
}

void MainWindow::onTogglePasswordVisibility() {
  passwordEdit_->setEchoMode(togglePasswordButton_->isChecked()
                                 ? QLineEdit::Normal
                                 : QLineEdit::Password);
}

void MainWindow::onEncrypt() {
  const QString inputFile = inputPathEdit_->text();
  const QString password = passwordEdit_->text();

  if (inputFile.isEmpty() || password.isEmpty()) {
    QMessageBox::warning(
        this, QStringLiteral("Error"),
        QStringLiteral("Please select a file and enter a password."));
    return;
  }

  std::string error_msg;
  if (!validate_password(password.toStdString(), error_msg)) {
    QMessageBox::warning(this, QStringLiteral("Weak Password"),
                         QString::fromStdString(error_msg));
    return;
  }

  const QString outputFile = QString::fromStdString(
      auto_generate_output_filename(inputFile.toStdString(), "encrypt"));

  progressBar_->show();
  statusLabel_->setText(QStringLiteral("Encrypting..."));
  encryptButton_->setEnabled(false);
  decryptButton_->setEnabled(false);
  QApplication::processEvents();

  try {
    const std::string input_path = inputFile.toStdString();
    const std::string output_path = outputFile.toStdString();
    std::string pass_str = password.toStdString();

    std::ifstream infile(input_path, std::ios::binary);
    if (!infile) {
      throw std::runtime_error("Cannot open input file");
    }

    auto salt = EntropyManager::get_instance().get_bytes(SALT_SIZE);
    auto key = derive_key(pass_str.c_str(), pass_str.size(), salt);
    auto nonce = EntropyManager::get_instance().get_bytes(NONCE_SIZE);

    std::vector<unsigned char> plaintext(
        (std::istreambuf_iterator<char>(infile)),
        std::istreambuf_iterator<char>());
    infile.close();

    auto ciphertext = encrypt_aes256gcm(plaintext, key, nonce);
    secure_wipe_vector(plaintext);
    secure_wipe_vector(key);

    std::ofstream outfile(output_path, std::ios::binary);
    if (!outfile) {
      throw std::runtime_error("Cannot open output file");
    }

    outfile.write(reinterpret_cast<const char *>(&FILE_FORMAT_VERSION), 1);
    outfile.write(reinterpret_cast<const char *>(salt.data()), SALT_SIZE);
    outfile.write(reinterpret_cast<const char *>(nonce.data()), NONCE_SIZE);

    const std::string ext = extract_extension(input_path);
    const auto ext_len = static_cast<unsigned char>(ext.length());
    outfile.write(reinterpret_cast<const char *>(&ext_len), 1);
    if (ext_len > 0) {
      outfile.write(ext.c_str(), ext_len);
    }

    constexpr unsigned char comp_byte = 0; // No compression for GUI MVP
    outfile.write(reinterpret_cast<const char *>(&comp_byte), 1);
    outfile.write(reinterpret_cast<const char *>(ciphertext.data()),
                  static_cast<std::streamsize>(ciphertext.size()));
    outfile.close();

    secure_wipe_string(pass_str);

    statusLabel_->setText(QStringLiteral("Encryption Successful!"));
    QMessageBox::information(
        this, QStringLiteral("Success"),
        QStringLiteral("File encrypted successfully!\nOutput: ") + outputFile);

  } catch (const std::exception &e) {
    statusLabel_->setText(QStringLiteral("Error"));
    QMessageBox::critical(
        this, QStringLiteral("Error"),
        QStringLiteral("Encryption failed: %1").arg(e.what()));
  }

  progressBar_->hide();
  encryptButton_->setEnabled(true);
  decryptButton_->setEnabled(true);
}

void MainWindow::onDecrypt() {
  const QString inputFile = inputPathEdit_->text();
  const QString password = passwordEdit_->text();

  if (inputFile.isEmpty() || password.isEmpty()) {
    QMessageBox::warning(
        this, QStringLiteral("Error"),
        QStringLiteral("Please select a file and enter a password."));
    return;
  }

  const QString outputFile = QString::fromStdString(
      auto_generate_output_filename(inputFile.toStdString(), "decrypt"));

  progressBar_->show();
  statusLabel_->setText(QStringLiteral("Decrypting..."));
  encryptButton_->setEnabled(false);
  decryptButton_->setEnabled(false);
  QApplication::processEvents();

  try {
    const std::string input_path = inputFile.toStdString();
    const std::string output_path = outputFile.toStdString();
    std::string pass_str = password.toStdString();

    std::ifstream infile(input_path, std::ios::binary);
    if (!infile) {
      throw std::runtime_error("Cannot open input file");
    }

    unsigned char version = 0;
    infile.read(reinterpret_cast<char *>(&version), 1);
    if (version != FILE_FORMAT_VERSION) {
      throw std::runtime_error("Invalid file format");
    }

    std::vector<unsigned char> salt(SALT_SIZE);
    infile.read(reinterpret_cast<char *>(salt.data()), SALT_SIZE);

    std::vector<unsigned char> nonce(NONCE_SIZE);
    infile.read(reinterpret_cast<char *>(nonce.data()), NONCE_SIZE);

    unsigned char ext_len = 0;
    infile.read(reinterpret_cast<char *>(&ext_len), 1);
    if (ext_len > 0) {
      infile.ignore(ext_len);
    }

    unsigned char comp_byte = 0;
    infile.read(reinterpret_cast<char *>(&comp_byte), 1);

    std::vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(infile)),
        std::istreambuf_iterator<char>());
    infile.close();

    auto key = derive_key(pass_str.c_str(), pass_str.size(), salt);
    auto plaintext = decrypt_aes256gcm(ciphertext, key, nonce);

    if (plaintext.empty()) {
      throw std::runtime_error("Decryption failed (wrong password?)");
    }

    // Decompress if file was compressed during encryption
    const auto comp_level = static_cast<CompressionLevel>(comp_byte);
    if (comp_level != CompressionLevel::NONE) {
      plaintext = decompress_data(plaintext);
      if (plaintext.empty()) {
        throw std::runtime_error("Decompression failed");
      }
    }

    std::ofstream outfile(output_path, std::ios::binary);
    if (!outfile) {
      throw std::runtime_error("Cannot open output file");
    }

    outfile.write(reinterpret_cast<const char *>(plaintext.data()),
                  static_cast<std::streamsize>(plaintext.size()));
    outfile.close();

    secure_wipe_vector(plaintext);
    secure_wipe_vector(key);
    secure_wipe_string(pass_str);

    statusLabel_->setText(QStringLiteral("Decryption Successful!"));
    QMessageBox::information(
        this, QStringLiteral("Success"),
        QStringLiteral("File decrypted successfully!\nOutput: ") + outputFile);

  } catch (const std::exception &e) {
    statusLabel_->setText(QStringLiteral("Error"));
    QMessageBox::critical(
        this, QStringLiteral("Error"),
        QStringLiteral("Decryption failed: %1").arg(e.what()));
  }

  progressBar_->hide();
  encryptButton_->setEnabled(true);
  decryptButton_->setEnabled(true);
}
