#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QIcon>

#include "nexapack_backend.hpp"

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    app.setApplicationName("NexaPack Studio");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("NexaPack Project");
    app.setOrganizationDomain("nexapack.io");

    QQmlApplicationEngine engine;

    nexapack::NexaPackBackend backend;
    engine.rootContext()->setContextProperty("nexapackBackend", &backend);

    const QUrl url(QStringLiteral("qrc:/qml/main.qml"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
                     &app, [url](QObject* obj, const QUrl& objUrl) {
        if (!obj && url == objUrl) {
            QCoreApplication::exit(-1);
        }
    }, Qt::QueuedConnection);

    engine.load(url);

    return app.exec();
}
