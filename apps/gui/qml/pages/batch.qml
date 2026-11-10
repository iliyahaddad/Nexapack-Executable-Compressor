import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

Page {
    id: batchPage

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
                        text: "Batch Processing"
                        font.pixelSize: 22
                        font.bold: true
                        color: "#ffffff"
                        Layout.alignment: Qt.AlignLeft
                    }

                    Text {
                        text: "Pack multiple executables at once"
                        font.pixelSize: 13
                        color: "#888888"
                        Layout.alignment: Qt.AlignLeft
                    }

                    Text {
                        text: "Select a directory containing executables to pack them all"
                        font.pixelSize: 13
                        color: "#888888"
                        Layout.alignment: Qt.AlignLeft
                    }

                    RowLayout {
                        spacing: 12
                        Layout.fillWidth: true

                        TextField {
                            id: batchDir
                            placeholderText: "Select directory..."
                            readOnly: true
                            Layout.fillWidth: true
                        }

                        Button {
                            text: "Browse"
                            onClicked: {
                                const fileDialog = Qt.createQmlObject('import QtQuick 2.15; import QtQuick.Dialogs 1.15; FileDialog { }', batchDir);
                                fileDialog.title = "Select Directory";
                                fileDialog.selectFolder = true;
                                fileDialog.folder = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation);
                                fileDialog.onAccepted = {
                                    batchDir.text = fileDialog.fileUrl;
                                }
                                fileDialog.open();
                            }
                        }
                    }

                    ComboBox {
                        id: batchCodec
                        model: nexapackBackend.codecs
                        currentIndex: 1
                        Layout.fillWidth: true
                    }

                    ComboBox {
                        id: batchProfile
                        model: nexapackBackend.profiles
                        currentIndex: 1
                        Layout.fillWidth: true
                    }

                    Button {
                        text: "Start Batch"
                        Layout.fillWidth: true
                        enabled: !nexapackBackend.isBusy && !!batchDir.text
                        onClicked: {
                            batchStatus.text = "Batch processing: " + batchDir.text;
                            batchProgress.value = 0;
                        }
                    }

                    ProgressBar {
                        id: batchProgress
                        Layout.fillWidth: true
                        value: 0
                    }

                    Text {
                        id: batchStatus
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
