import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Item {
    id: root
    property string title: ""
    property string subtitle: ""
    property int progress: 0
    property string status: ""
    property bool indeterminate: false
    Layout.fillWidth: true
    Layout.preferredHeight: 140

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
        spacing: 10

        RowLayout {
            Layout.fillWidth: true
            Text {
                text: root.title
                font.family: "Inter, Segoe UI, sans-serif"
                font.pointSize: 15
                font.weight: Font.Bold
                color: "#e8e8f0"
            }
            Item { Layout.fillWidth: true }
            Text {
                text: root.status
                font.pointSize: 11
                color: root.status === "success" ? "#22c55e" :
                       root.status === "error" ? "#ef4444" : "#a8a8b8"
            }
        }

        Text {
            text: root.subtitle
            font.pointSize: 10
            color: "#a8a8b8"
        }

        ProgressBar {
            Layout.fillWidth: true
            value: root.progress
            from: 0
            to: 100
        }
    }
}
