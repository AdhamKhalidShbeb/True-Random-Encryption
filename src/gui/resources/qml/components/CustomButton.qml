import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Button {
    id: control
    text: "Button"
    property color baseColor: "#ffb400" // Primary
    property color hoverColor: "#ffc840"
    property color pressedColor: "#cc9000"
    property color textColor: "#000000"
    property bool isPrimary: true

    contentItem: Text {
        text: control.text
        font.pixelSize: 14
        font.bold: true
        font.family: "Inter, Roboto, sans-serif"
        opacity: enabled ? 1.0 : 0.3
        color: control.isPrimary ? control.textColor : "#B8860B"
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }

    background: Rectangle {
        implicitWidth: 120
        implicitHeight: 40
        opacity: enabled ? 1 : 0.3
        color: control.isPrimary ? (control.down ? control.pressedColor : (control.hovered ? control.hoverColor : control.baseColor)) : "transparent"
        border.color: control.baseColor
        border.width: 2
        radius: 4
    }
}
