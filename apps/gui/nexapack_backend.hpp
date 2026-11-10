#ifndef NEXAPACK_BACKEND_HPP
#define NEXAPACK_BACKEND_HPP

#include <QObject>
#include <QString>
#include <QVariant>
#include <QList>
#include <QMap>

#include <codecs/codec_registry.hpp>
#include <core/analyzer/analyzer.hpp>
#include <core/planner/planner.hpp>
#include <core/codec_interface.hpp>
#include <protection/nexaprotect/nexaprotect.hpp>

namespace nexapack {

class NexaPackBackend : public QObject {
    Q_OBJECT

    Q_PROPERTY(QString version READ version NOTIFY versionChanged)
    Q_PROPERTY(QStringList codecs READ codecs NOTIFY codecsChanged)
    Q_PROPERTY(QStringList profiles READ profiles NOTIFY profilesChanged)
    Q_PROPERTY(QStringList protectionProfiles READ protectionProfiles NOTIFY protectionProfilesChanged)
    Q_PROPERTY(bool isBusy READ isBusy NOTIFY isBusyChanged)
    Q_PROPERTY(QString currentStatus READ currentStatus NOTIFY currentStatusChanged)

public:
    explicit NexaPackBackend(QObject* parent = nullptr);

    QString version() const;
    QStringList codecs() const;
    QStringList profiles() const;
    QStringList protectionProfiles() const;
    bool isBusy() const;
    QString currentStatus() const;

    Q_INVOKABLE QVariantMap analyzeExecutable(const QString& filePath);
    Q_INVOKABLE QVariantMap packExecutable(const QString& inputPath,
                                           const QString& outputPath,
                                           const QString& codec,
                                           const QString& profile,
                                           const QString& protectionProfile,
                                           uint32_t level);
    Q_INVOKABLE QVariantMap unpackExecutable(const QString& inputPath,
                                             const QString& outputPath);
    Q_INVOKABLE QVariantMap verifyExecutable(const QString& filePath);
    Q_INVOKABLE QVariantMap benchmarkExecutable(const QString& filePath);
    Q_INVOKABLE QVariantList listCodecs();

signals:
    void versionChanged();
    void codecsChanged();
    void profilesChanged();
    void protectionProfilesChanged();
    void isBusyChanged();
    void currentStatusChanged();
    void packingProgress(int percent);
    void packingFinished(bool success, const QString& message);
    void unpackingFinished(bool success, const QString& message);
    void verificationFinished(bool success, const QString& message);

private:
    QString m_version;
    QStringList m_codecs;
    QStringList m_profiles;
    QStringList m_protectionProfiles;
    bool m_isBusy;
    QString m_currentStatus;

    void setBusy(bool busy);
    void setStatus(const QString& status);
};

} // namespace nexapack

#endif // NEXAPACK_BACKEND_HPP
