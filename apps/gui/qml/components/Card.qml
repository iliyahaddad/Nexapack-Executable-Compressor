import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Item {
    id: root
    property string title: ""
    property string subtitle: ""
    property color accent: "#7c5cff"
    Layout.fillWidth: true
    Layout.preferredHeight: 120

    Rectangle {
        id: cardBg
        anchors.fill: parent
        color: "#1a1a22"
        border.color: "#333340"
        border.width: 1
        radius: 12
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: 20
        anchors.topMargin: 16
        anchors.rightMargin: 20
        anchors.bottomMargin: 16
        spacing: 8

        Text {
            text: root.title
            font.family: "Inter, Segoe UI, sans-serif"
            font.pointSize: 16
            font.weight: Font.Bold
            color: "#e8e8f0"
            Layout.alignment: Qt.AlignLeft
        }

        Text {
            text: root.subtitle
            font.pointSize: 11
            color: "#a8a8b8"
            Layout.alignment: Qt.AlignLeft
            wrapMode: Text.Wrap
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: "#333340"
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            anchors.topMargin: 4
        }
    }
}
