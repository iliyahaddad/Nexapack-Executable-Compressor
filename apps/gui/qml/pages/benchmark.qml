import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

Page {
    id: benchmarkPage

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
                        text: "Benchmark"
                        font.pixelSize: 22
                        font.bold: true
                        color: "#ffffff"
                        Layout.alignment: Qt.AlignLeft
                    }

                    Text {
                        text: "Compare compression algorithms on your executable"
                        font.pixelSize: 13
                        color: "#888888"
                        Layout.alignment: Qt.AlignLeft
                    }

                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        TextField {
                            id: benchInput
                            placeholderText: "Select executable to benchmark..."
                            readOnly: true
                            Layout.fillWidth: true
                        }

                        Button {
                            text: "Browse"
                            onClicked: {
                                const fileDialog = Qt.createQmlObject('import QtQuick 2.15; import QtQuick.Dialogs 1.15; FileDialog { }', benchInput);
                                fileDialog.title = "Select Executable";
                                fileDialog.folder = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation);
                                fileDialog.nameFilters = ["Executables (*.exe *.dll)", "All files (*)"];
                                fileDialog.onAccepted = {
                                    benchInput.text = fileDialog.fileUrl;
                                }
                                fileDialog.open();
                            }
                        }
                    }

                    Button {
                        text: "Run Benchmark"
                        icon.name: "speedometer"
                        Layout.fillWidth: true
                        enabled: !nexapackBackend.isBusy && !!benchInput.text
                        onClicked: {
                            if (!benchInput.text) {
                                benchStatus.text = "Please select an executable";
                                return;
                            }
                            benchResults.model = null;
                            benchBestCodec.text = "";
                            benchBestLevel.text = "";
                            benchBestSize.text = "";
                            const result = nexapackBackend.benchmarkExecutable(benchInput.text);
                            if (result.success) {
                                benchFormat.text = result.format;
                                benchArch.text = result.architecture;
                                benchOriginalSize.text = result.originalSize + " bytes";
                                benchBestCodec.text = result.bestCodec;
                                benchBestLevel.text = result.bestLevel.toString();
                                benchBestSize.text = result.bestSize + " bytes";
                                benchResults.model = result.codecResults;
                                benchStatus.text = "Benchmark complete";
                            } else {
                                benchStatus.text = "Error: " + (result.error || "Unknown error");
                            }
                        }
                    }

                    Rectangle {
                        color: "#323232"
                        radius: 6
                        Layout.fillWidth: true

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 16
                            spacing: 10

                            Text {
                                text: "File Information"
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
                                    Text { id: benchFormat; color: "#ffffff"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Architecture:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: benchArch; color: "#ffffff"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Original Size:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: benchOriginalSize; color: "#ffffff"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Best Codec:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: benchBestCodec; color: "#00ff00"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Best Level:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: benchBestLevel; color: "#ffffff"; font.pixelSize: 12; }
                                }
                                RowLayout {
                                    Text { text: "Best Final Size:"; color: "#888888"; font.pixelSize: 12; }
                                    Text { id: benchBestSize; color: "#ffffff"; font.pixelSize: 12; }
                                }
                            }
                        }
                    }

                    TableView {
                        id: benchResults
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        model: benchResults.model || []

                        delegate: Rectangle {
                            color: index % 2 === 0 ? "#2a2a2a" : "#323232"
                            implicitWidth: 100
                            implicitHeight: 30

                            Text {
                                text: model.codec
                                color: "#ffffff"
                                font.pixelSize: 12
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.left: parent.left
                                anchors.leftMargin: 8
                            }
                        }

                        ColumnDelegate {
                            width: 100
                            role: "codec"
                            delegate: Rectangle {
                                color: "#2d2d2d"
                                Text {
                                    text: display
                                    color: "#ffffff"
                                    font.pixelSize: 12
                                    anchors.fill: parent
                                    anchors.verticalCenter: parent.verticalCenter
                                    padding: 8
                                }
                            }
                        }
                    }

                    Text {
                        id: benchStatus
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
