import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

Page {
    id: settingsPage

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
                    anchors.margins: 20
                    spacing: 16

                    Text {
                        text: "Settings"
                        font.pixelSize: 22
                        font.bold: true
                        color: "#ffffff"
                        Layout.alignment: Qt.AlignLeft
                    }

                    GroupBox {
                        title: "Theme"
                        Layout.fillWidth: true

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 12

                            RowLayout {
                                spacing: 12
                                Layout.fillWidth: true

                                RadioButton {
                                    text: "Dark"
                                    checked: true
                                    onToggled: {
                                        if (checked) Material.theme = Material.Dark;
                                    }
                                }

                                RadioButton {
                                    text: "Light"
                                    onToggled: {
                                        if (checked) Material.theme = Material.Light;
                                    }
                                }
                            }
                        }
                    }

                    GroupBox {
                        title: "Default Output Directory"
                        Layout.fillWidth: true

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 12

                            RowLayout {
                                spacing: 12
                                Layout.fillWidth: true

                                TextField {
                                    text: QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation)
                                    readOnly: true
                                    Layout.fillWidth: true
                                }

                                Button {
                                    text: "Change"
                                    Layout.preferredWidth: 100
                                }
                            }
                        }
                    }

                    GroupBox {
                        title: "Performance"
                        Layout.fillWidth: true

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 12

                            RowLayout {
                                spacing: 12
                                Layout.fillWidth: true

                                Text { text: "Compression Threads:"; color: "#cccccc"; font.pixelSize: 13; Layout.alignment: Qt.AlignVCenter; }

                                SpinBox {
                                    from: 1
                                    to: 16
                                    value: 4
                                    Layout.fillWidth: true
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
