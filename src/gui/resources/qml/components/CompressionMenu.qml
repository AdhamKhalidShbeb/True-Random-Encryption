import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Popup {
    id: root
    width: 240
    height: contentHeight
    padding: 0
    topMargin: 8
    
    background: Rectangle {
        color: "#16191b"
        border.color: "#333333"
        border.width: 1
        radius: 12
        clip: true
    }
    
    contentItem: ColumnLayout {
        width: parent.width
        spacing: 2
        anchors.margins: 4
        
        Repeater {
            model: [
                { label: "None", value: 0, desc: "No compression, fastest speed" },
                { label: "Balanced", value: 2, desc: "Optimal size & speed ratio" },
                { label: "Maximum", value: 3, desc: "High compression, slower" },
                { label: "Ultra", value: 4, desc: "Smallest size, slowest" }
            ]
            
            delegate: Rectangle {
                id: itemDelegate
                Layout.fillWidth: true
                Layout.preferredHeight: 48
                Layout.leftMargin: 4
                Layout.rightMargin: 4
                
                color: isHovered ? "#222527" : (isSelected ? "#1c1f21" : "transparent")
                radius: 8
                
                property bool isSelected: backend.compression === modelData.value
                property bool isHovered: false
                
                Behavior on color { ColorAnimation { duration: 150 } }
                
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 12
                    anchors.rightMargin: 12
                    spacing: 12
                    
                    // Selection Indicator (Checkmark)
                    Item {
                        Layout.preferredWidth: 20
                        Layout.preferredHeight: 20
                        Layout.alignment: Qt.AlignVCenter
                        
                        Rectangle {
                            anchors.centerIn: parent
                            width: 20
                            height: 20
                            radius: 10
                            color: itemDelegate.isSelected ? "#ffb400" : "transparent"
                            border.color: itemDelegate.isSelected ? "#ffb400" : "#444444"
                            border.width: 1.5
                            
                            Behavior on color { ColorAnimation { duration: 200 } }
                            Behavior on border.color { ColorAnimation { duration: 200 } }
                            
                            Text {
                                anchors.centerIn: parent
                                text: "✓"
                                color: "#16191b"
                                font.pixelSize: 12
                                font.bold: true
                                visible: itemDelegate.isSelected
                            }
                        }
                    }
                    
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignVCenter
                        spacing: 2
                        
                        Text {
                            text: modelData.label
                            color: itemDelegate.isSelected ? "#FFFFFF" : "#DDDDDD"
                            font.pixelSize: 14
                            font.bold: true
                        }
                        
                        Text {
                            text: modelData.desc
                            color: itemDelegate.isSelected ? "#aaaaaa" : "#666666"
                            font.pixelSize: 11
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                    }
                }
                
                MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onEntered: itemDelegate.isHovered = true
                    onExited: itemDelegate.isHovered = false
                    onClicked: {
                        console.log("Clicked option:", modelData.label, "Value:", modelData.value)
                        backend.compression = modelData.value
                        root.close()
                    }
                }
            }
        }
        
        // Bottom spacer
        Item { Layout.preferredHeight: 4 }
    }
    
    enter: Transition {
        NumberAnimation { property: "opacity"; from: 0.0; to: 1.0; duration: 150 }
        NumberAnimation { property: "scale"; from: 0.95; to: 1.0; duration: 150; easing.type: Easing.OutQuad }
    }
    
    exit: Transition {
        NumberAnimation { property: "opacity"; from: 1.0; to: 0.0; duration: 100 }
    }
}
