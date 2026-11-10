import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

Page {
    id: dashboardPage

    ScrollView {
        anchors.fill: parent

        ColumnLayout {
            anchors.fill: parent
            spacing: 20
            anchors.margins: 20

            // Header section
            Rectangle {
                color: "#2a2a2a"
                radius: 8
                Layout.fillWidth: true

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 20
                    spacing: 12

                    Text {
                        text: "Dashboard"
                        font.pixelSize: 24
                        font.bold: true
                        color: "#ffffff"
                        Layout.alignment: Qt.AlignLeft
                    }

                    Text {
                        text: "NexaPack Executive Packer - Professional executable compression and protection"
                        font.pixelSize: 14
                        color: "#888888"
                        wrapMode: Text.Wrap
                        Layout.alignment: Qt.AlignLeft
                    }
                }
            }

            // Quick stats row
            RowLayout {
                spacing: 12
                Layout.fillWidth: true

                StatCard {
                    title: "Version"
                    value: "1.0.0"
                    subtitle: "Release Candidate"
                }

                StatCard {
                    title: "Codecs"
                    value: nexapackBackend.codecs.length
                    subtitle: "Available compression methods"
                }

                StatCard {
                    title: "Platform"
                    value: "Windows x64"
                    subtitle: "PE32+ EXE / DLL"
                }

                StatCard {
                    title: "Status"
                    value: nexapackBackend.isBusy ? "Busy" : "Ready"
                    subtitle: nexapackBackend.currentStatus
                }
            }

            // Recent operations
            Rectangle {
                color: "#2a2a2a"
                radius: 8
                Layout.fillWidth: true
                Layout.fillHeight: true

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 20
                    spacing: 12

                    Text {
                        text: "Quick Actions"
                        font.pixelSize: 18
                        font.bold: true
                        color: "#ffffff"
                        Layout.alignment: Qt.AlignLeft
                    }

                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        Button {
                            text: "Pack Executable"
                            icon.name: "package"
                            Layout.fillWidth: true
                            onClicked: root.currentPage = "pack"
                        }

                        Button {
                            text: "Inspect File"
                            icon.name: "search"
                            Layout.fillWidth: true
                            onClicked: root.currentPage = "inspect"
                        }

                        Button {
                            text: "Unpack File"
                            icon.name: "folder-open"
                            Layout.fillWidth: true
                            onClicked: root.currentPage = "unpack"
                        }

                        Button {
                            text: "Benchmark"
                            icon.name: "speedometer"
                            Layout.fillWidth: true
                            onClicked: root.currentPage = "benchmark"
                        }
                    }

                    Text {
                        text: "Supported Codecs: " + nexapackBackend.codecs.join(", ")
                        font.pixelSize: 12
                        color: "#888888"
                        wrapMode: Text.Wrap
                        Layout.alignment: Qt.AlignLeft
                    }

                    Text {
                        text: "Supported Profiles: " + nexapackBackend.profiles.join(", ")
                        font.pixelSize: 12
                        color: "#888888"
                        wrapMode: Text.Wrap
                        Layout.alignment: Qt.AlignLeft
                    }
                }
            }
        }
    }
}

// Reusable stat card component
Component {
    id: statCard
    Rectangle {
        color: "#2a2a2a"
        radius: 8
        Layout.fillWidth: true
        Layout.preferredWidth: 200

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 16
            spacing: 8

            Text {
                text: statCard.title
                font.pixelSize: 12
                color: "#888888"
                Layout.alignment: Qt.AlignLeft
            }

            Text {
                text: statCard.value
                font.pixelSize: 28
                font.bold: true
                color: "#ffffff"
                Layout.alignment: Qt.AlignLeft
            }

            Text {
                text: statCard.subtitle
                font.pixelSize: 11
                color: "#666666"
                Layout.alignment: Qt.AlignLeft
            }
        }
    }
}