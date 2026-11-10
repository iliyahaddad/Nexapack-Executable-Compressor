import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

Page {
    id: packPage

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
                        text: "Pack Executable"
                        font.pixelSize: 22
                        font.bold: true
                        color: "#ffffff"
                        Layout.alignment: Qt.AlignLeft
                    }

                    // File selection
                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        TextField {
                            id: inputField
                            placeholderText: "Select executable to pack..."
                            readOnly: true
                            Layout.fillWidth: true
                        }

                        Button {
                            text: "Browse"
                            onClicked: {
                                const result = Qt.openUrlExternally("");
                                const fileDialog = Qt.createQmlObject('import QtQuick 2.15; import QtQuick.Dialogs 1.15; FileDialog { }', inputField);
                                fileDialog.title = "Select Executable";
                                fileDialog.folder = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation);
                                fileDialog.nameFilters = ["Executables (*.exe *.dll)", "All files (*)"];
                                fileDialog.onAccepted = {
                                    inputField.text = fileDialog.fileUrl;
                                }
                                fileDialog.open();
                            }
                        }
                    }

                    // Output path
                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        TextField {
                            id: outputField
                            placeholderText: "Output .nxp file (optional)..."
                            readOnly: true
                            Layout.fillWidth: true
                        }

                        Button {
                            text: "Browse"
                            onClicked: {
                                const fileDialog = Qt.createQmlObject('import QtQuick 2.15; import QtQuick.Dialogs 1.15; FileDialog { }', outputField);
                                fileDialog.title = "Save Packed File";
                                fileDialog.folder = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation);
                                fileDialog.nameFilters = ["NexaPack (*.nxp)", "All files (*)"];
                                fileDialog.onAccepted = {
                                    outputField.text = fileDialog.fileUrl;
                                }
                                fileDialog.open();
                            }
                        }
                    }

                    // Codec selection
                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        Text {
                            text: "Codec:"
                            color: "#cccccc"
                            font.pixelSize: 13
                            Layout.alignment: Qt.AlignVCenter
                        }

                        ComboBox {
                            id: codecCombo
                            model: nexapackBackend.codecs
                            currentIndex: 1
                            Layout.fillWidth: true
                        }

                        Text {
                            text: "Level:"
                            color: "#cccccc"
                            font.pixelSize: 13
                            Layout.alignment: Qt.AlignVCenter
                        }

                        SpinBox {
                            id: levelSpin
                            from: 1
                            to: 9
                            value: 6
                            Layout.preferredWidth: 80
                        }
                    }

                    // Profile selection
                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        Text {
                            text: "Profile:"
                            color: "#cccccc"
                            font.pixelSize: 13
                            Layout.alignment: Qt.AlignVCenter
                        }

                        ComboBox {
                            id: profileCombo
                            model: nexapackBackend.profiles
                            currentIndex: 1
                            Layout.fillWidth: true
                        }

                        Text {
                            text: "Protection:"
                            color: "#cccccc"
                            font.pixelSize: 13
                            Layout.alignment: Qt.AlignVCenter
                        }

                        ComboBox {
                            id: protectionCombo
                            model: nexapackBackend.protectionProfiles
                            currentIndex: 0
                            Layout.fillWidth: true
                        }
                    }

                    // Pack button
                    Button {
                        text: "Pack Now"
                        icon.name: "package"
                        Layout.fillWidth: true
                        Material.foreground: Material.Blue
                        enabled: !nexapackBackend.isBusy
                        onClicked: {
                            if (!inputField.text) {
                                statusText.text = "Please select an input file";
                                return;
                            }
                            const output = outputField.text || inputField.text + ".nxp";
                            outputField.text = output;
                            const result = nexapackBackend.packExecutable(
                                inputField.text,
                                output,
                                codecCombo.currentText,
                                profileCombo.currentText,
                                protectionCombo.currentText,
                                levelSpin.value
                            );
                            if (!result.success) {
                                statusText.text = "Error: " + (result.error || "Unknown error");
                            } else {
                                statusText.text = "Packing started...";
                            }
                        }
                    }

                    // Progress bar
                    ProgressBar {
                        id: packProgress
                        Layout.fillWidth: true
                        value: 0
                        visible: nexapackBackend.isBusy
                    }

                    // Status text
                    Text {
                        id: statusText
                        text: nexapackBackend.currentStatus
                        color: "#888888"
                        font.pixelSize: 12
                        Layout.alignment: Qt.AlignLeft
                    }

                    Connections {
                        target: nexapackBackend
                        onPackingProgress: packProgress.value = percent
                        onPackingFinished: {
                            packProgress.value = 100;
                            statusText.text = message;
                            if (success) {
                                inputField.text = "";
                                outputField.text = "";
                            }
                        }
                    }
                }
            }
        }
    }
}
