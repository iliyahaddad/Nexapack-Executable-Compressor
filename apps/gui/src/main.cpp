#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>

#include "src/backend.hpp"

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    app.setOrganizationName("NexaPack");
    app.setOrganizationDomain("nexapack.dev");
    app.setApplicationName("NexaPack Studio");

    nexapack::Backend backend;

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("nexapackBackend", &backend);

    const QUrl url(QStringLiteral("qrc:/qml/main.qml"));
    QObject::connect(
        &engine, &QQmlApplicationEngine::objectCreationFailed, &app,
        []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);
    engine.load(url);

    return app.exec();
}
