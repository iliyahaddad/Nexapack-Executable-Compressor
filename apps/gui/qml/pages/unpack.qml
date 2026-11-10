import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

Page {
    id: unpackPage

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
                        text: "Unpack Executable"
                        font.pixelSize: 22
                        font.bold: true
                        color: "#ffffff"
                        Layout.alignment: Qt.AlignLeft
                    }

                    Text {
                        text: "Reconstruct the original executable from a packed .nxp file"
                        font.pixelSize: 13
                        color: "#888888"
                        Layout.alignment: Qt.AlignLeft
                    }

                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        TextField {
                            id: unpackInput
                            placeholderText: "Select .nxp file to unpack..."
                            readOnly: true
                            Layout.fillWidth: true
                        }

                        Button {
                            text: "Browse"
                            onClicked: {
                                const fileDialog = Qt.createQmlObject('import QtQuick 2.15; import QtQuick.Dialogs 1.15; FileDialog { }', unpackInput);
                                fileDialog.title = "Select Packed File";
                                fileDialog.folder = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation);
                                fileDialog.nameFilters = ["NexaPack (*.nxp)", "All files (*)"];
                                fileDialog.onAccepted = {
                                    unpackInput.text = fileDialog.fileUrl;
                                }
                                fileDialog.open();
                            }
                        }
                    }

                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        TextField {
                            id: unpackOutput
                            placeholderText: "Output original executable..."
                            readOnly: true
                            Layout.fillWidth: true
                        }

                        Button {
                            text: "Browse"
                            onClicked: {
                                const fileDialog = Qt.createQmlObject('import QtQuick 2.15; import QtQuick.Dialogs 1.15; FileDialog { }', unpackOutput);
                                fileDialog.title = "Save Original File";
                                fileDialog.folder = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation);
                                fileDialog.nameFilters = ["Executables (*.exe *.dll)", "All files (*)"];
                                fileDialog.onAccepted = {
                                    unpackOutput.text = fileDialog.fileUrl;
                                }
                                fileDialog.open();
                            }
                        }
                    }

                    Button {
                        text: "Unpack Now"
                        icon.name: "folder-open"
                        Layout.fillWidth: true
                        enabled: !nexapackBackend.isBusy && !!unpackInput.text
                        onClicked: {
                            if (!unpackInput.text) {
                                statusText.text = "Please select a .nxp file";
                                return;
                            }
                            const output = unpackOutput.text || unpackInput.text.replace(/\.nxp$/, "") + "_unpacked.exe";
                            unpackOutput.text = output;
                            const result = nexapackBackend.unpackExecutable(
                                unpackInput.text,
                                output
                            );
                            if (!result.success) {
                                statusText.text = "Error: " + (result.error || "Unknown error");
                            } else {
                                statusText.text = "Unpacking started...";
                            }
                        }
                    }

                    ProgressBar {
                        id: unpackProgress
                        Layout.fillWidth: true
                        value: 0
                        visible: nexapackBackend.isBusy
                    }

                    Text {
                        id: statusText
                        text: nexapackBackend.currentStatus
                        color: "#888888"
                        font.pixelSize: 12
                        Layout.alignment: Qt.AlignLeft
                    }

                    Connections {
                        target: nexapackBackend
                        onUnpackingFinished: {
                            unpackProgress.value = 100;
                            statusText.text = message;
                            if (success) {
                                unpackInput.text = "";
                                unpackOutput.text = "";
                            }
                        }
                    }
                }
            }
        }
    }
}
