#include "MainWindow.hpp"
#include "../core/CryptoCore.hpp"
#include "../entropy/EntropyManager.hpp"
#include "compression/CompressionManager.hpp"
#include <QApplication>
#include <QFile>
#include <QGroupBox>
#include <QScrollArea>
#include <QStyle>
#include <QThread>
#include <fstream>

using namespace TRE;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), currentCompression_(0), isVerbose_(false),
      secureDelete_(false) {
  setupUi();
  applyTheme();
  setAcceptDrops(true);
}

MainWindow::~MainWindow() {}

void MainWindow::setupUi() {
  setWindowTitle("True Random Encryption");
  setMinimumSize(450, 650);
  setMaximumHeight(650);
  resize(500, 650);

  // The content widget that holds the actual UI
  QWidget *contentWidget = new QWidget(this);
  setCentralWidget(contentWidget);

  QVBoxLayout *mainLayout = new QVBoxLayout(contentWidget);
  mainLayout->setSpacing(10);
  mainLayout->setContentsMargins(15, 15, 15, 15);

  // ===== HEADER =====
  QLabel *titleLabel = new QLabel("True Random Encryption", this);
  titleLabel->setObjectName("titleLabel");
  titleLabel->setAlignment(Qt::AlignCenter);
  mainLayout->addWidget(titleLabel);

  QLabel *subtitleLabel = new QLabel(
      "Military-Grade File Encryption with Hardware True-Randomness", this);
  subtitleLabel->setObjectName("subtitleLabel");
  subtitleLabel->setAlignment(Qt::AlignCenter);
  mainLayout->addWidget(subtitleLabel);

  // ===== INPUT FILES GROUP =====
  QGroupBox *inputGroup = new QGroupBox("Input Files", this);
  inputGroup->setObjectName("inputGroup");
  QVBoxLayout *inputLayout = new QVBoxLayout(inputGroup);
  inputLayout->setContentsMargins(10, 15, 10, 10);
  inputLayout->setSpacing(8);

  // Frame for the list to give it a distinct box look
  QFrame *listFrame = new QFrame(inputGroup);
  listFrame->setObjectName("listFrame");
  QGridLayout *listFrameLayout = new QGridLayout(listFrame);
  listFrameLayout->setContentsMargins(0, 0, 0, 0);

  fileListWidget_ = new QListWidget(listFrame);
  fileListWidget_->setObjectName("fileList");
  fileListWidget_->setMinimumHeight(120);
  fileListWidget_->setSelectionMode(QAbstractItemView::ExtendedSelection);

  fileTypeLabel_ = new QLabel("DROP FILES OR FOLDERS HERE", listFrame);
  fileTypeLabel_->setObjectName("fileTypeLabel");
  fileTypeLabel_->setAlignment(Qt::AlignCenter);
  fileTypeLabel_->setAttribute(Qt::WA_TransparentForMouseEvents);
  fileTypeLabel_->setStyleSheet(
      "color: rgba(0, 243, 255, 0.4); font-weight: 800; font-size: 14px; "
      "letter-spacing: 1px;");

  listFrameLayout->addWidget(fileListWidget_, 0, 0);
  listFrameLayout->addWidget(fileTypeLabel_, 0, 0);
  inputLayout->addWidget(listFrame, 1);

  QHBoxLayout *browseLayout = new QHBoxLayout();
  browseLayout->setContentsMargins(0, 5, 0, 0); // Add some top margin
  browseLayout->setSpacing(10);
  browseFileButton_ = new QPushButton("FILES", inputGroup);
  browseFileButton_->setObjectName("browseFileButton");
  browseFileButton_->setMinimumHeight(32);
  browseFolderButton_ = new QPushButton("FOLDERS", inputGroup);
  browseFolderButton_->setObjectName("browseFolderButton");
  browseFolderButton_->setMinimumHeight(32);
  clearButton_ = new QPushButton("CLEAR", inputGroup);
  clearButton_->setObjectName("clearButton");
  clearButton_->setMinimumHeight(32);

  browseLayout->addWidget(browseFileButton_, 1);
  browseLayout->addWidget(browseFolderButton_, 1);
  browseLayout->addWidget(clearButton_, 1);
  inputLayout->addLayout(browseLayout);
  mainLayout->addWidget(inputGroup, 1); // Give it stretch

  // ===== PASSWORD GROUP =====
  QGroupBox *passwordGroup = new QGroupBox("Password", this);
  passwordGroup->setObjectName("passwordGroup");
  QVBoxLayout *passLayout = new QVBoxLayout(passwordGroup);

  QHBoxLayout *passInputLayout = new QHBoxLayout();
  passwordEdit_ = new QLineEdit(this);
  passwordEdit_->setEchoMode(QLineEdit::Password);
  passwordEdit_->setPlaceholderText(
      "Enter secure password (16+ chars, mixed case, digits, symbols)");
  passwordEdit_->setObjectName("passwordEdit");

  togglePasswordButton_ = new QPushButton(this);
  togglePasswordButton_->setObjectName("togglePasswordButton");
  togglePasswordButton_->setFixedWidth(32);
  togglePasswordButton_->setFixedHeight(32);
  togglePasswordButton_->setCheckable(true);
  togglePasswordButton_->setIcon(QIcon(":/eye_closed.png"));
  togglePasswordButton_->setIconSize(QSize(24, 24));
  togglePasswordButton_->setToolTip("Show/Hide Password");

  passInputLayout->addWidget(passwordEdit_);
  passInputLayout->addWidget(togglePasswordButton_);
  passLayout->addLayout(passInputLayout);

  // Password strength
  QHBoxLayout *strengthLayout = new QHBoxLayout();
  strengthBar_ = new QProgressBar(this);
  strengthBar_->setObjectName("strengthBar");
  strengthBar_->setRange(0, 100);
  strengthBar_->setValue(0);
  strengthBar_->setTextVisible(false);
  strengthBar_->setFixedHeight(8);

  strengthLabel_ = new QLabel("Enter password", this);
  strengthLabel_->setObjectName("strengthLabel");

  strengthLayout->addWidget(strengthBar_, 3);
  strengthLayout->addWidget(strengthLabel_, 1);
  passLayout->addLayout(strengthLayout);
  mainLayout->addWidget(passwordGroup);

  // ===== OPTIONS GROUP =====
  QGroupBox *optionsGroup = new QGroupBox("Options", this);
  optionsGroup->setObjectName("optionsGroup");
  QGridLayout *optionsLayout = new QGridLayout(optionsGroup);

  QLabel *compLabel = new QLabel("Compression:", this);
  compressionCombo_ = new QComboBox(this);
  compressionCombo_->setObjectName("compressionCombo");
  compressionCombo_->setMinimumWidth(120);
  compressionCombo_->addItem("None", 0);
  compressionCombo_->addItem("Fast", 1);
  compressionCombo_->addItem("Balanced", 2);
  compressionCombo_->addItem("Maximum", 3);
  compressionCombo_->addItem("Ultra", 4);
  for (int i = 0; i < compressionCombo_->count(); ++i) {
    compressionCombo_->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
  }
  compressionCombo_->setCurrentIndex(2); // Default: Balanced

  verboseCheck_ = new QCheckBox("Verbose mode", this);
  verboseCheck_->setObjectName("verboseCheck");

  secureDeleteCheck_ = new QCheckBox("Secure delete original", this);
  secureDeleteCheck_->setObjectName("secureDeleteCheck");

  optionsLayout->addWidget(compLabel, 0, 0);
  optionsLayout->addWidget(compressionCombo_, 0, 1, Qt::AlignLeft);
  optionsLayout->addWidget(verboseCheck_, 1, 0, 1, 2);
  optionsLayout->addWidget(secureDeleteCheck_, 1, 2, 1, 2);
  optionsLayout->setColumnStretch(3, 1); // Push everything to the left
  mainLayout->addWidget(optionsGroup);

  // ===== ACTION BUTTONS =====
  QHBoxLayout *actionLayout = new QHBoxLayout();
  actionLayout->setSpacing(20);

  encryptButton_ = new QPushButton("ENCRYPT", this);
  encryptButton_->setObjectName("encryptButton");
  encryptButton_->setMinimumHeight(45);

  decryptButton_ = new QPushButton("DECRYPT", this);
  decryptButton_->setObjectName("decryptButton");
  decryptButton_->setMinimumHeight(45);

  actionLayout->addWidget(encryptButton_);
  actionLayout->addWidget(decryptButton_);
  mainLayout->addLayout(actionLayout);

  // ===== PROGRESS & STATUS =====
  progressBar_ = new QProgressBar(this);
  progressBar_->setObjectName("mainProgressBar");
  progressBar_->setTextVisible(true);
  progressBar_->setRange(0, 100);
  progressBar_->setValue(0);
  progressBar_->hide();
  mainLayout->addWidget(progressBar_);

  statusLabel_ = new QLabel("Ready", this);
  statusLabel_->setObjectName("statusLabel");
  statusLabel_->setAlignment(Qt::AlignCenter);
  mainLayout->addWidget(statusLabel_);

  detailLabel_ = new QLabel("", this);
  detailLabel_->setObjectName("detailLabel");
  detailLabel_->setAlignment(Qt::AlignCenter);
  mainLayout->addWidget(detailLabel_);

  mainLayout->addStretch(1); // Push everything up

  // ===== CONNECTIONS =====
  connect(browseFileButton_, &QPushButton::clicked, this,
          &MainWindow::onBrowseFile);
  connect(browseFolderButton_, &QPushButton::clicked, this,
          &MainWindow::onBrowseFolder);
  connect(clearButton_, &QPushButton::clicked, this, &MainWindow::onClearFiles);
  connect(encryptButton_, &QPushButton::clicked, this, &MainWindow::onEncrypt);
  connect(decryptButton_, &QPushButton::clicked, this, &MainWindow::onDecrypt);
  connect(togglePasswordButton_, &QPushButton::toggled, this,
          &MainWindow::onTogglePasswordVisibility);
  connect(passwordEdit_, &QLineEdit::textChanged, this,
          &MainWindow::onPasswordChanged);
  connect(compressionCombo_,
          QOverload<int>::of(&QComboBox::currentIndexChanged), this,
          &MainWindow::onCompressionChanged);
}

void MainWindow::applyTheme() {
  QFile file(":/style.qss");
  if (file.open(QFile::ReadOnly)) {
    qApp->setStyleSheet(QLatin1String(file.readAll()));
  }
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event) {
  if (event->mimeData()->hasUrls()) {
    event->acceptProposedAction();
  }
}

void MainWindow::dropEvent(QDropEvent *event) {
  const QMimeData *mimeData = event->mimeData();
  if (mimeData->hasUrls()) {
    QStringList paths;
    for (const QUrl &url : mimeData->urls()) {
      paths.append(url.toLocalFile());
    }
    addFilesToList(paths);
  }
}

void MainWindow::onBrowseFile() {
  QStringList files = QFileDialog::getOpenFileNames(this, "Select Files");
  if (!files.isEmpty()) {
    addFilesToList(files);
  }
}

void MainWindow::onBrowseFolder() {
  QString folder = QFileDialog::getExistingDirectory(this, "Select Folder");
  if (!folder.isEmpty()) {
    addFilesToList(QStringList() << folder);
  }
}

void MainWindow::onClearFiles() {
  fileListWidget_->clear();
  updateFileTypeLabel();
}

void MainWindow::addFilesToList(const QStringList &paths) {
  for (const QString &path : paths) {
    QFileInfo info(path);
    if (info.exists()) {
      QString icon = info.isDir() ? "[DIR] " : "[FILE] ";
      QString displayName = icon + info.fileName();

      QListWidgetItem *item = new QListWidgetItem(displayName);
      item->setData(Qt::UserRole, path);
      item->setToolTip(path);
      fileListWidget_->addItem(item);
    }
  }
  updateFileTypeLabel();
}

void MainWindow::updateFileTypeLabel() {
  int count = fileListWidget_->count();
  if (count == 0) {
    fileTypeLabel_->show();
  } else {
    fileTypeLabel_->hide();
  }
}

bool MainWindow::isFolder(const QString &path) {
  return QFileInfo(path).isDir();
}

void MainWindow::onTogglePasswordVisibility() {
  bool checked = togglePasswordButton_->isChecked();
  passwordEdit_->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
  togglePasswordButton_->setIcon(
      QIcon(checked ? ":/eye_open.png" : ":/eye_closed.png"));
}

void MainWindow::onPasswordChanged(const QString &text) {
  updatePasswordStrength(text);
}

void MainWindow::updatePasswordStrength(const QString &password) {
  if (password.isEmpty()) {
    strengthBar_->setValue(0);
    strengthLabel_->setText("Enter password");
    strengthBar_->setStyleSheet(
        "QProgressBar::chunk { background-color: #555; }");
    return;
  }

  int score = 0;
  qsizetype len = password.length();

  // Length scoring
  if (len >= 8)
    score += 10;
  if (len >= 12)
    score += 15;
  if (len >= 16)
    score += 25;
  if (len >= 20)
    score += 10;

  // Character variety
  bool hasUpper = false, hasLower = false, hasDigit = false, hasSymbol = false;
  int upperCount = 0, lowerCount = 0, digitCount = 0, symbolCount = 0;

  for (const QChar &c : password) {
    if (c.isUpper()) {
      hasUpper = true;
      upperCount++;
    } else if (c.isLower()) {
      hasLower = true;
      lowerCount++;
    } else if (c.isDigit()) {
      hasDigit = true;
      digitCount++;
    } else {
      hasSymbol = true;
      symbolCount++;
    }
  }

  if (hasUpper)
    score += 10;
  if (hasLower)
    score += 10;
  if (hasDigit)
    score += 10;
  if (hasSymbol)
    score += 10;

  // Extra for meeting requirements
  if (upperCount >= 2)
    score += 5;
  if (lowerCount >= 2)
    score += 5;
  if (digitCount >= 2)
    score += 5;
  if (symbolCount >= 2)
    score += 5;

  std::string error_msg;
  bool meets_requirements =
      validate_password(password.toStdString(), error_msg);

  if (!meets_requirements) {
    // If it doesn't meet requirements, cap the score at 80 and show "Weak" or
    // "Moderate"
    score = qMin(score, 80);
  }

  score = qMin(score, 100);
  strengthBar_->setValue(score);

  QString label;
  QString color;
  if (!meets_requirements) {
    label = "Requirements Not Met";
    color = "#ff0055"; // Neon Red
  } else if (score < 90) {
    label = "Strong";
    color = "#00ff9d"; // Neon Green
  } else {
    label = "Very Strong";
    color = "#00f3ff"; // Neon Cyan
  }

  strengthLabel_->setText(label);
  strengthBar_->setStyleSheet(
      QString(
          "QProgressBar::chunk { background-color: %1; border-radius: 4px; }")
          .arg(color));
}

void MainWindow::onCompressionChanged(int index) {
  currentCompression_ = compressionCombo_->itemData(index).toInt();
}

void MainWindow::setStatus(const QString &message, bool isError) {
  statusLabel_->setText(message);
  if (isError) {
    statusLabel_->setStyleSheet("color: #ff0055;"); // Neon Red
  } else {
    statusLabel_->setStyleSheet("color: #00ff9d;"); // Neon Green
  }
}

void MainWindow::setProgress(int value, int max) {
  progressBar_->setMaximum(max);
  progressBar_->setValue(value);
}

void MainWindow::onEncrypt() {
  if (fileListWidget_->count() == 0) {
    QMessageBox::warning(this, "Error",
                         "Please select files or folders to encrypt.");
    return;
  }

  QString password = passwordEdit_->text();
  if (password.isEmpty()) {
    QMessageBox::warning(this, "Error", "Please enter a password.");
    return;
  }

  std::string error_msg;
  if (!validate_password(password.toStdString(), error_msg)) {
    QMessageBox::warning(this, "Weak Password",
                         QString::fromStdString(error_msg));
    return;
  }

  progressBar_->show();
  encryptButton_->setEnabled(false);
  decryptButton_->setEnabled(false);

  isVerbose_ = verboseCheck_->isChecked();
  secureDelete_ = secureDeleteCheck_->isChecked();

  int total = fileListWidget_->count();
  int success = 0;
  int failed = 0;

  for (int i = 0; i < total; i++) {
    QString path = fileListWidget_->item(i)->data(Qt::UserRole).toString();
    QString name = QFileInfo(path).fileName();

    setStatus(
        QString("Encrypting %1 of %2: %3").arg(i + 1).arg(total).arg(name));
    setProgress(i, total);
    QApplication::processEvents();

    try {
      std::string input_path = path.toStdString();
      std::string output_path =
          auto_generate_output_filename(input_path, "encrypt");
      std::string pass_str = password.toStdString();

      std::ifstream infile(input_path, std::ios::binary);
      if (!infile)
        throw std::runtime_error("Cannot open input file");

      std::vector<unsigned char> salt =
          EntropyManager::get_instance().get_bytes(SALT_SIZE);
      std::vector<unsigned char> key =
          derive_key(pass_str.c_str(), pass_str.size(), salt);
      std::vector<unsigned char> nonce =
          EntropyManager::get_instance().get_bytes(NONCE_SIZE);

      std::vector<unsigned char> plaintext(
          (std::istreambuf_iterator<char>(infile)),
          std::istreambuf_iterator<char>());
      infile.close();

      // Apply compression
      if (currentCompression_ > 0) {
        CompressionLevel level =
            static_cast<CompressionLevel>(currentCompression_);
        plaintext = compress_data(plaintext, level, isVerbose_);
      }

      std::vector<unsigned char> ciphertext =
          encrypt_aes256gcm(plaintext, key, nonce);
      secure_wipe_vector(plaintext);

      // Extract extension for storage
      std::string ext = extract_extension(input_path);
      unsigned char ext_len = static_cast<unsigned char>(ext.length());

      std::ofstream outfile(output_path, std::ios::binary);
      if (!outfile)
        throw std::runtime_error("Cannot open output file");

      // Write file format: VERSION(1) + EXT_LEN(1) + EXT(N) + SALT(128) +
      // NONCE(12) + COMP(1) + CIPHERTEXT
      outfile.write(reinterpret_cast<const char *>(&FILE_FORMAT_VERSION), 1);
      outfile.write(reinterpret_cast<const char *>(&ext_len), 1);
      if (ext_len > 0)
        outfile.write(ext.c_str(), ext_len);
      outfile.write(reinterpret_cast<const char *>(salt.data()),
                    static_cast<std::streamsize>(SALT_SIZE));
      outfile.write(reinterpret_cast<const char *>(nonce.data()),
                    static_cast<std::streamsize>(NONCE_SIZE));

      unsigned char comp_byte = static_cast<unsigned char>(currentCompression_);
      outfile.write(reinterpret_cast<const char *>(&comp_byte), 1);

      outfile.write(reinterpret_cast<const char *>(ciphertext.data()),
                    static_cast<std::streamsize>(ciphertext.size()));
      outfile.close();

      if (secureDelete_) {
        (void)secure_delete_file(input_path); // Ignore return value
      }

      success++;
    } catch (const std::exception &e) {
      failed++;
      detailLabel_->setText(QString("Error: %1").arg(e.what()));
    }
  }

  setProgress(total, total);
  progressBar_->hide();
  encryptButton_->setEnabled(true);
  decryptButton_->setEnabled(true);

  QString result = QString("Encrypted %1 of %2 items").arg(success).arg(total);
  if (failed > 0)
    result += QString(" (%1 failed)").arg(failed);
  setStatus(result, failed > 0);

  if (success > 0) {
    QMessageBox::information(this, "Success", result);
  }
}

void MainWindow::onDecrypt() {
  if (fileListWidget_->count() == 0) {
    QMessageBox::warning(this, "Error",
                         "Please select encrypted files to decrypt.");
    return;
  }

  QString password = passwordEdit_->text();
  if (password.isEmpty()) {
    QMessageBox::warning(this, "Error", "Please enter the password.");
    return;
  }

  progressBar_->show();
  encryptButton_->setEnabled(false);
  decryptButton_->setEnabled(false);

  int total = fileListWidget_->count();
  int success = 0;
  int failed = 0;

  for (int i = 0; i < total; i++) {
    QString path = fileListWidget_->item(i)->data(Qt::UserRole).toString();
    QString name = QFileInfo(path).fileName();

    setStatus(
        QString("Decrypting %1 of %2: %3").arg(i + 1).arg(total).arg(name));
    setProgress(i, total);
    QApplication::processEvents();

    try {
      std::string input_path = path.toStdString();
      std::string output_path =
          auto_generate_output_filename(input_path, "decrypt");
      std::string pass_str = password.toStdString();

      std::ifstream infile(input_path, std::ios::binary);
      if (!infile)
        throw std::runtime_error("Cannot open input file");

      // Read file format: VERSION(1) + EXT_LEN(1) + EXT(N) + SALT(128) +
      // NONCE(12) + COMP(1) + CIPHERTEXT
      unsigned char version;
      infile.read(reinterpret_cast<char *>(&version), 1);
      if (version != FILE_FORMAT_VERSION)
        throw std::runtime_error("Invalid file format version");

      unsigned char ext_len;
      infile.read(reinterpret_cast<char *>(&ext_len), 1);
      std::string stored_ext;
      if (ext_len > 0) {
        stored_ext.resize(ext_len);
        infile.read(&stored_ext[0], ext_len);
      }

      std::vector<unsigned char> salt(SALT_SIZE);
      infile.read(reinterpret_cast<char *>(salt.data()), SALT_SIZE);

      std::vector<unsigned char> nonce(NONCE_SIZE);
      infile.read(reinterpret_cast<char *>(nonce.data()), NONCE_SIZE);

      unsigned char comp_byte;
      infile.read(reinterpret_cast<char *>(&comp_byte), 1);
      CompressionLevel comp_level = static_cast<CompressionLevel>(comp_byte);

      std::vector<unsigned char> ciphertext(
          (std::istreambuf_iterator<char>(infile)),
          std::istreambuf_iterator<char>());
      infile.close();

      std::vector<unsigned char> key =
          derive_key(pass_str.c_str(), pass_str.size(), salt);
      std::vector<unsigned char> plaintext =
          decrypt_aes256gcm(ciphertext, key, nonce);

      if (plaintext.empty())
        throw std::runtime_error("Decryption failed (wrong password?)");

      // Decompress if needed
      if (comp_level != CompressionLevel::NONE) {
        plaintext = decompress_data(plaintext, isVerbose_);
        if (plaintext.empty())
          throw std::runtime_error("Decompression failed");
      }

      std::ofstream outfile(output_path, std::ios::binary);
      if (!outfile)
        throw std::runtime_error("Cannot open output file");

      outfile.write(reinterpret_cast<const char *>(plaintext.data()),
                    static_cast<std::streamsize>(plaintext.size()));
      outfile.close();

      secure_wipe_vector(plaintext);
      success++;
    } catch (const std::exception &e) {
      failed++;
      detailLabel_->setText(QString("Error: %1").arg(e.what()));
    }
  }

  setProgress(total, total);
  progressBar_->hide();
  encryptButton_->setEnabled(true);
  decryptButton_->setEnabled(true);

  QString result = QString("Decrypted %1 of %2 items").arg(success).arg(total);
  if (failed > 0)
    result += QString(" (%1 failed)").arg(failed);
  setStatus(result, failed > 0);

  if (success > 0) {
    QMessageBox::information(this, "Success", result);
  }
}
