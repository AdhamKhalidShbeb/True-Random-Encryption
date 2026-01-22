import QtQuick
import QtQuick.Controls

Rectangle {
    id: root
    color: dropArea.containsDrag ? "#1a1d21" : "#121416"
    border.color: dropArea.containsDrag ? "#ffb400" : "#1b1f21"
    border.width: dropArea.containsDrag ? 2 : 1
    radius: 8
    
    Behavior on color { ColorAnimation { duration: 250 } }
    Behavior on border.width { NumberAnimation { duration: 250 } }
    
    states: [
        State {
            name: "active"
            when: dropArea.containsDrag
            PropertyChanges { target: root; color: "#1a1d21"; border.width: 2 }
            PropertyChanges { target: cloudIcon; scale: 1.2 }
            PropertyChanges { target: label; color: "#ffb400"; font.bold: true }
            PropertyChanges { target: subLabel; opacity: 0 }
        }
    ]

    transitions: [
        Transition {
            from: ""; to: "active"
            ParallelAnimation {
                ColorAnimation { duration: 250 }
                NumberAnimation { properties: "border.width,opacity,scale"; duration: 250; easing.type: Easing.OutCubic }
            }
        },
        Transition {
            from: "active"; to: ""
            ParallelAnimation {
                ColorAnimation { duration: 250 }
                NumberAnimation { properties: "border.width,opacity,scale"; duration: 250; easing.type: Easing.InCubic }
            }
        }
    ]

    SequentialAnimation on border.color {
        running: dropArea.containsDrag
        loops: Animation.Infinite
        ColorAnimation { from: "#ffb400"; to: "#ff8c00"; duration: 800 }
        ColorAnimation { from: "#ff8c00"; to: "#ffb400"; duration: 800 }
    }
    
    onStateChanged: {
        if (state === "") {
            border.color = "#1b1f21"
        }
    }
    
    signal filesDropped(var urls)
    signal clicked()

    property alias text: label.text

    DropArea {
        id: dropArea
        anchors.fill: parent
        onEntered: (drag) => {
            drag.accept(Qt.LinkAction);
        }
        onDropped: (drop) => {
            if (drop.hasUrls) {
                root.filesDropped(drop.urls)
            }
        }
    }

    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: root.clicked()
    }

    Column {
        anchors.centerIn: parent
        spacing: 16
        
        Image {
            id: cloudIcon
            source: "qrc:/upload_cloud.svg"
            width: 48
            height: 48
            fillMode: Image.PreserveAspectFit
            anchors.horizontalCenter: parent.horizontalCenter
            opacity: 1.0
            scale: 1.0
            smooth: true
            mipmap: true
            
            SequentialAnimation on y {
                running: dropArea.containsDrag
                loops: Animation.Infinite
                NumberAnimation { from: 0; to: -8; duration: 1000; easing.type: Easing.InOutQuad }
                NumberAnimation { from: -8; to: 0; duration: 1000; easing.type: Easing.InOutQuad }
            }
        }

        Column {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: 4
            
            Text {
                id: label
                text: "Drop files or folders here"
                color: "#CCCCCC"
                font.pixelSize: 16
                font.family: "Inter, Roboto, sans-serif"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Text {
                id: subLabel
                text: "or click to browse from disk"
                color: "#666666"
                font.pixelSize: 12
                font.family: "Inter, Roboto, sans-serif"
                anchors.horizontalCenter: parent.horizontalCenter
            }
        }
    }
}
