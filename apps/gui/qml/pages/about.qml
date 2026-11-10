import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

Page {
    id: aboutPage

    ScrollView {
        anchors.fill: parent

        ColumnLayout {
            anchors.fill: parent
            spacing: 20
            anchors.margins: 20

            Rectangle {
                color: "#2a2a2a"
                radius: 8
                Layout.fillWidth: true

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 30
                    spacing: 20

                    Image {
                        source: "qrc:/qml/assets/logo.png"
                        width: 96
                        height: 96
                        fillMode: Image.PreserveAspectFit
                        Layout.alignment: Qt.AlignHCenter
                    }

                    Text {
                        text: "NexaPack Studio"
                        font.pixelSize: 32
                        font.bold: true
                        color: "#ffffff"
                        Layout.alignment: Qt.AlignHCenter
                    }

                    Text {
                        text: "Version 1.0.0 (Release Candidate)"
                        font.pixelSize: 16
                        color: "#888888"
                        Layout.alignment: Qt.AlignHCenter
                    }

                    Text {
                        text: "An independent, professional executable compression and protection product"
                        font.pixelSize: 14
                        color: "#aaaaaa"
                        wrapMode: Text.Wrap
                        Layout.alignment: Qt.AlignHCenter
                    }

                    Text {
                        text: "Built with Qt 6.12.0 and C++20"
                        font.pixelSize: 12
                        color: "#666666"
                        Layout.alignment: Qt.AlignHCenter
                    }

                    Rectangle {
                        color: "#323232"
                        radius: 6
                        Layout.fillWidth: true

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 16
                            spacing: 12

                            Text {
                                text: "Third-Party Libraries"
                                font.pixelSize: 16
                                font.bold: true
                                color: "#ffffff"
                                Layout.alignment: Qt.AlignLeft
                            }

                            Text {
                                text: "Zstandard (BSD 3-Clause) - facebook/zstd v1.6.0"
                                font.pixelSize: 12
                                color: "#cccccc"
                                Layout.alignment: Qt.AlignLeft
                            }

                            Text {
                                text: "LZ4 (BSD 2-Clause) - lz4/lz4 v1.11.0"
                                font.pixelSize: 12
                                color: "#cccccc"
                                Layout.alignment: Qt.AlignLeft
                            }

                            Text {
                                text: "LZMA SDK (Permissive) - Igor Pavlov v16.06"
                                font.pixelSize: 12
                                color: "#cccccc"
                                Layout.alignment: Qt.AlignLeft
                            }

                            Text {
                                text: "See docs/THIRD_PARTY_NOTICES.md for full license details"
                                font.pixelSize: 11
                                color: "#666666"
                                Layout.alignment: Qt.AlignLeft
                            }
                        }
                    }

                    Text {
                        text: "Copyright (c) 2026 NexaPack Project. All rights reserved."
                        font.pixelSize: 11
                        color: "#666666"
                        Layout.alignment: Qt.AlignHCenter
                    }
                }
            }
        }
    }
}
