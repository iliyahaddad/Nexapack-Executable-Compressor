import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15

ApplicationWindow {
    id: root
    visible: true
    width: 1200
    height: 800
    minimumWidth: 900
    minimumHeight: 600
    title: "NexaPack Studio v1.0.0"

    Material.theme: Material.Dark
    Material.accent: Material.Blue

    // Navigation state
    property string currentPage: "dashboard"

    // Header
    Rectangle {
        id: header
        height: 60
        color: "#1e1e1e"
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right

        RowLayout {
            anchors.fill: parent
            anchors.margins: 16

            Image {
                source: "qrc:/qml/assets/logo.png"
                width: 32
                height: 32
                fillMode: Image.PreserveAspectFit
            }

            Text {
                text: "NexaPack Studio"
                font.pixelSize: 20
                font.bold: true
                color: "#ffffff"
                Layout.alignment: Qt.AlignVCenter
            }

            Item { Layout.fillWidth: true }

            Button {
                text: "v" + nexapackBackend.version
                flat: true
                enabled: false
                Layout.alignment: Qt.AlignVCenter
            }
        }
    }

    // Main content area
    StackLayout {
        id: contentStack
        anchors.top: header.bottom
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        currentIndex: {
            if (currentPage === "dashboard") return 0
            if (currentPage === "pack") return 1
            if (currentPage === "inspect") return 2
            if (currentPage === "unpack") return 3
            if (currentPage === "benchmark") return 4
            if (currentPage === "batch") return 5
            if (currentPage === "settings") return 6
            if (currentPage === "about") return 7
            return 0
        }

        DashboardPage { id: dashboardPage }
        PackPage { id: packPage }
        InspectPage { id: inspectPage }
        UnpackPage { id: unpackPage }
        BenchmarkPage { id: benchmarkPage }
        BatchPage { id: batchPage }
        SettingsPage { id: settingsPage }
        AboutPage { id: aboutPage }
    }

    // Bottom status bar
    Rectangle {
        id: statusBar
        height: 30
        color: "#252525"
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right

        Text {
            text: nexapackBackend.currentStatus
            color: "#aaaaaa"
            font.pixelSize: 12
            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left
            anchors.leftMargin: 16
        }

        Rectangle {
            width: 1
            height: parent.height * 0.6
            color: "#3a3a3a"
            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left
            anchors.leftMargin: 300
        }

        Text {
            text: nexapackBackend.isBusy ? "Working..." : "Idle"
            color: nexapackBackend.isBusy ? "#ffaa00" : "#00ff00"
            font.pixelSize: 12
            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left
            anchors.leftMargin: 310
        }
    }
}
