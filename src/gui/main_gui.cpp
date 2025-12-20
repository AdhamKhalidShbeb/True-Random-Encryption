#include "MainWindow.hpp"
#include <QApplication>
#include <QMessageBox>
#include <sodium.h>

int main(int argc, char *argv[]) {
  // Initialize libsodium before any crypto operations
  if (sodium_init() < 0) {
    QApplication app(argc, argv);
    QMessageBox::critical(nullptr, "Fatal Error",
                          "Failed to initialize crypto library (libsodium).");
    return 1;
  }

  QApplication app(argc, argv);

  // Set application metadata
  app.setApplicationName("True Random Encryption");
  app.setApplicationVersion("4.0");
  app.setOrganizationName("TRE Team");

  MainWindow window;
  window.show();

  return app.exec();
}
