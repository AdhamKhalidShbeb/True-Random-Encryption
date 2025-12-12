#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QPushButton>
#include <QVBoxLayout>

class MainWindow : public QMainWindow {
  Q_OBJECT

public:
  explicit MainWindow(QWidget *parent = nullptr);
  ~MainWindow() override;

  // Non-copyable, non-movable
  MainWindow(const MainWindow &) = delete;
  MainWindow &operator=(const MainWindow &) = delete;
  MainWindow(MainWindow &&) = delete;
  MainWindow &operator=(MainWindow &&) = delete;

protected:
  void dragEnterEvent(QDragEnterEvent *event) override;
  void dropEvent(QDropEvent *event) override;

private slots:
  void onBrowseInput();
  void onEncrypt();
  void onDecrypt();
  void onTogglePasswordVisibility();

private:
  void setupUi();
  void applyTheme();

  // UI Elements
  QLineEdit *inputPathEdit_ = nullptr;
  QLineEdit *passwordEdit_ = nullptr;
  QPushButton *browseButton_ = nullptr;
  QPushButton *encryptButton_ = nullptr;
  QPushButton *decryptButton_ = nullptr;
  QPushButton *togglePasswordButton_ = nullptr;
  QProgressBar *progressBar_ = nullptr;
  QLabel *statusLabel_ = nullptr;
};

#endif // MAINWINDOW_HPP
