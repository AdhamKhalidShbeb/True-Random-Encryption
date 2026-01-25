#include "Backend.hpp"
#include <QGuiApplication>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <iostream>
#include <sodium.h>

int main(int argc, char *argv[]) {
  if (sodium_init() < 0) {
    std::cerr << "Failed to init crypto\n";
    return 1;
  }

  qputenv("QT_QUICK_CONTROLS_STYLE", "Basic");
  QQuickStyle::setStyle("Basic");

  QGuiApplication app(argc, argv);
  app.setWindowIcon(QIcon(":/icon.png"));
  app.setApplicationName("True Random Encryption");
  app.setApplicationVersion("1.0.0");
  app.setOrganizationName("TRE Team");

  Backend backend;
  QQmlApplicationEngine engine;
  engine.rootContext()->setContextProperty("backend", &backend);

  const QUrl url(QStringLiteral("qrc:/qml/Main.qml"));
  QObject::connect(
      &engine, &QQmlApplicationEngine::objectCreated, &app,
      [url](QObject *obj, const QUrl &objUrl) {
        if (!obj && url == objUrl)
          QCoreApplication::exit(-1);
      },
      Qt::QueuedConnection);

  engine.load(url);
  return app.exec();
}
