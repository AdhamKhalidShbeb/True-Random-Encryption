#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QPushButton>
#include <QStringList>
#include <QVBoxLayout>
#include <QWidget>

class MainWindow : public QMainWindow {
  Q_OBJECT

public:
  explicit MainWindow(QWidget *parent = nullptr);
  ~MainWindow() override;

  enum class Theme { Dark, Light };

  MainWindow(const MainWindow &) = delete;
  MainWindow &operator=(const MainWindow &) = delete;
  MainWindow(MainWindow &&) = delete;
  MainWindow &operator=(MainWindow &&) = delete;

protected:
  void dragEnterEvent(QDragEnterEvent *event) override;
  void dropEvent(QDropEvent *event) override;

private slots:
  void onBrowseFile();
  void onBrowseFolder();
  void onClearFiles();
  void onEncrypt();
  void onDecrypt();
  void onTogglePasswordVisibility();
  void onPasswordChanged(const QString &text);
  void onCompressionChanged(int index);
  void onToggleTheme();

private:
  void setupUi();
  void applyTheme(Theme theme);
  void saveThemePreference(Theme theme);
  Theme loadThemePreference();
  void updateFileTypeLabel();
  void updatePasswordStrength(const QString &password);
  void addFilesToList(const QStringList &paths);
  bool isFolder(const QString &path);
  void setStatus(const QString &message, bool isError = false);
  void setProgress(int value, int max = 100);
  QIcon getFileIcon(const QFileInfo &info);
  // UI Elements - Input
  QListWidget *fileListWidget_;
  QLabel *fileTypeLabel_;
  QPushButton *browseFileButton_;
  QPushButton *browseFolderButton_;
  QPushButton *clearButton_;

  // UI Elements - Password
  QLineEdit *passwordEdit_;
  QPushButton *togglePasswordButton_;
  QProgressBar *strengthBar_;
  QLabel *strengthLabel_;

  // UI Elements - Options
  QComboBox *compressionCombo_;
  QCheckBox *verboseCheck_;
  QCheckBox *secureDeleteCheck_;

  // UI Elements - Actions
  QPushButton *encryptButton_;
  QPushButton *decryptButton_;
  QPushButton *themeToggleButton_;

  // UI Elements - Status
  QProgressBar *progressBar_;
  QLabel *statusLabel_;
  QLabel *detailLabel_;

  // State
  int currentCompression_;
  bool isVerbose_;
  bool secureDelete_;
  Theme currentTheme_;
};

#endif // MAINWINDOW_HPP
