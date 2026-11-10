import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

Page {
    id: inspectPage

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
                        text: "Inspect Executable"
                        font.pixelSize: 22
                        font.bold: true
                        color: "#ffffff"
                        Layout.alignment: Qt.AlignLeft
                    }

                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        TextField {
                            id: inspectInput
                            placeholderText: "Select executable to inspect..."
                            readOnly: true
                            Layout.fillWidth: true
                        }

                        Button {
                            text: "Browse"
                            onClicked: {
                                const fileDialog = Qt.createQmlObject('import QtQuick 2.15; import QtQuick.Dialogs 1.15; FileDialog { }', inspectInput);
                                fileDialog.title = "Select Executable";
                                fileDialog.folder = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation);
                                fileDialog.nameFilters = ["Executables (*.exe *.dll)", "All files (*)"];
                                fileDialog.onAccepted = {
                                    inspectInput.text = fileDialog.fileUrl;
                                    doInspect();
                                }
                                fileDialog.open();
                            }
                        }
                    }

                    Button {
                        text: "Inspect"
                        Layout.fillWidth: true
                        enabled: !nexapackBackend.isBusy && !!inspectInput.text
                        onClicked: doInspect()
                    }

                    function doInspect() {
                        const result = nexapackBackend.analyzeExecutable(inspectInput.text);
                        if (result.success) {
                            inspectResults.visible = true;
                            formatValue.text = result.format;
                            archValue.text = result.architecture;
                            sizeValue.text = result.size + " bytes";
                            packableValue.text = result.packable ? "Yes" : "No";
                            executableValue.text = result.executable ? "Yes" : "No";
                            compatibilityValue.text = result.compatibility;
                            notesModel.clear();
                            for (let i = 0; i < result.notes.length; i++) {
                                notesModel.append({ note: result.notes[i] });
                            }
                            statusText.text = "Inspection complete";
                        } else {
                            statusText.text = "Error: " + (result.error || "Unknown error");
                        }
                    }

                    Rectangle {
                        id: inspectResults
                        visible: false
                        color: "#323232"
                        radius: 6
                        Layout.fillWidth: true

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 16
                            spacing: 10

                            Text {
                                text: "Analysis Results"
                                font.pixelSize: 16
                                font.bold: true
                                color: "#ffffff"
                                Layout.alignment: Qt.AlignLeft
                            }

                            GridLayout {
                                columns: 2
                                spacing: 12
                                Layout.fillWidth: true

                                RowLayout {
                                    Text { text: "Format:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: formatValue; color: "#ffffff"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Architecture:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: archValue; color: "#ffffff"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Size:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: sizeValue; color: "#ffffff"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Packable:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: packableValue; color: result.packable ? "#00ff00" : "#ff0000"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Executable:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: executableValue; color: "#ffffff"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Compatibility:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: compatibilityValue; color: "#ffffff"; font.pixelSize: 12; }
                                }
                            }

                            ListView {
                                id: notesList
                                Layout.fillWidth: true
                                Layout.preferredHeight: 100
                                model: notesModel
                                delegate: Text {
                                    text: modelData.note
                                    color: "#cccccc"
                                    font.pixelSize: 12
                                    wrapMode: Text.Wrap
                                    width: notesList.width
                                }
                            }
                        }
                    }

                    ListModel { id: notesModel }

                    Text {
                        id: statusText
                        text: "Ready"
                        color: "#888888"
                        font.pixelSize: 12
                        Layout.alignment: Qt.AlignLeft
                    }
                }
            }
        }
    }
}
