#ifndef NEXAPACK_STUDIO_BACKEND_HPP
#define NEXAPACK_STUDIO_BACKEND_HPP

#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QVector>

#include "core/codec_interface.hpp"
#include "core/analyzer/analyzer.hpp"
#include "core/planner/planner.hpp"
#include "core/error.hpp"
#include "core/metadata.hpp"

namespace nexapack {

// C++ backend exposed to QML. Provides the same core engine as the CLI,
// so the GUI never duplicates compression logic.
class Backend : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString version READ version NOTIFY versionChanged)
    Q_PROPERTY(QVariantMap codecs READ codecs NOTIFY codecsChanged)
    Q_PROPERTY(QStringList profiles READ profiles NOTIFY profilesChanged)
    Q_PROPERTY(QString platform READ platform NOTIFY platformChanged)

public:
    explicit Backend(QObject* parent = nullptr);
    ~Backend() override;

    QString version() const;
    QVariantMap codecs() const;
    QStringList profiles() const;
    QString platform() const;

    // Analyze an executable file and return a variant map report.
    Q_INVOKABLE QVariantMap inspectFile(const QString& path);

    // Pack a file with the given options.
    Q_INVOKABLE QVariantMap packFile(const QString& input,
                                     const QString& output,
                                     const QString& profile,
                                     const QString& codec,
                                     const QString& protection);

    // Unpack a NexaPack file.
    Q_INVOKABLE QVariantMap unpackFile(const QString& input,
                                       const QString& output);

signals:
    void versionChanged();
    void codecsChanged();
    void profilesChanged();
    void platformChanged();
    void operationStarted(const QString& op);
    void operationProgress(int percent);
    void operationFinished(const QString& op, bool success,
                           const QString& message);

private:
    std::unique_ptr<CodecRegistry> registry_;
};

} // namespace nexapack

#endif // NEXAPACK_STUDIO_BACKEND_HPP
