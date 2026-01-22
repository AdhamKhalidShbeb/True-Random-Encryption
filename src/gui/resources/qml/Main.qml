import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import QtQuick.Templates as T
import "components"

ApplicationWindow {
    id: window
    width: 540
    height: 820
    minimumWidth: 540
    maximumWidth: 540
    minimumHeight: 820
    maximumHeight: 820
    visible: true
    title: "True Random Encryption"
    color: "#0f1113"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 12

        // ---- Header ----
        RowLayout {
            Layout.fillWidth: true

            Column {
                Text {
                    text: "True Random\nEncryption"
                    color: "#FFFFFF"
                    font.pixelSize: 28
                    font.bold: true
                    lineHeight: 1.2
                }
                Text {
                    text: "Local, offline, military-grade file security"
                    color: "#888888"
                    font.pixelSize: 12
                    topPadding: 4
                }
            }

            Item { Layout.fillWidth: true }

            Column {
                Layout.alignment: Qt.AlignTop | Qt.AlignRight
                spacing: 8

                Text {
                    text: "v1.0"
                    color: "#444444"
                    font.pixelSize: 12
                    font.bold: true
                    anchors.right: parent.right
                }
            }
        }



        // ---- File Input ----
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 8

            Text {
                text: "INPUT FILES"
                    color: "#666666"
                    font.pixelSize: 12
                    font.bold: true
                    font.letterSpacing: 1
                }
                
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 16
                    
                    FileDropArea {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 140
                        onFilesDropped: (urls) => backend.addFiles(urls)
                        onClicked: fileDialog.open()
                    }
                    
                    // File List / Status
                    Rectangle {
                        id: fileListContainer
                        Layout.preferredWidth: 200
                        Layout.preferredHeight: 140
                        color: "#121416" // Card
                        border.color: "#1b1f21" // Secondary/Border
                        radius: 8
                        
                        ListView {
                            id: fileListView
                            anchors.fill: parent
                            anchors.margins: 8
                            clip: true
                            model: backend.files
                            
                            function getFileIcon(path) {
                                var ext = path.split('.').pop().toLowerCase();
                                if (["jpg", "jpeg", "png", "gif", "bmp", "svg", "webp"].includes(ext)) return "qrc:/file_image.svg";
                                if (["mp4", "mkv", "avi", "mov", "wmv", "flv", "webm"].includes(ext)) return "qrc:/file_video.svg";
                                if (["mp3", "wav", "ogg", "flac", "m4a", "aac"].includes(ext)) return "qrc:/file_audio.svg";
                                if (["zip", "tar", "gz", "7z", "rar", "xz"].includes(ext)) return "qrc:/file_archive.svg";
                                if (["cpp", "hpp", "c", "h", "js", "py", "html", "css", "json", "xml", "sh", "bat"].includes(ext)) return "qrc:/file_code.svg";
                                if (["pdf", "doc", "docx", "txt", "rtf", "odt"].includes(ext)) return "qrc:/file_doc.svg";
                                if (["xls", "xlsx", "csv", "ods"].includes(ext)) return "qrc:/file_excel.svg";
                                if (["exe", "msi", "bin", "app", "deb", "rpm"].includes(ext)) return "qrc:/file_exe.svg";
                                return "qrc:/file.svg";
                            }
                            
                            delegate: Item {
                                width: ListView.view.width
                                height: 32
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 8
                                    anchors.rightMargin: 24
                                    spacing: 12
                                    
                                    Image {
                                        source: fileListView.getFileIcon(modelData)
                                        width: 20
                                        height: 20
                                        Layout.preferredWidth: 20
                                        Layout.preferredHeight: 20
                                        fillMode: Image.PreserveAspectFit
                                        smooth: true
                                        mipmap: true
                                    }
                                    
                                    Text {
                                        text: modelData.split('/').pop() // Show filename only
                                        color: "#CCCCCC"
                                        font.pixelSize: 12
                                        elide: Text.ElideMiddle
                                        Layout.fillWidth: true
                                        verticalAlignment: Text.AlignVCenter
                                    }
                                    
                                    Text {
                                        text: "✕"
                                        color: "#666666"
                                        font.pixelSize: 14
                                        Layout.alignment: Qt.AlignVCenter
                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: backend.removeFile(index)
                                            hoverEnabled: true
                                            onEntered: parent.color = "#FF0055"
                                            onExited: parent.color = "#666666"
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Custom Scrollbar Track
                        Rectangle {
                            id: scrollTrack
                            visible: fileListView.count > 0
                            anchors.right: parent.right
                            anchors.rightMargin: 0
                            anchors.top: parent.top
                            anchors.topMargin: 6
                            anchors.bottom: parent.bottom
                            anchors.bottomMargin: 6
                            width: 4
                            color: "transparent"
                            
                            // Custom Scrollbar Handle
                            Rectangle {
                                id: scrollHandle
                                width: 2
                                height: Math.max(20, scrollTrack.height * fileListView.visibleArea.heightRatio)
                                y: Math.max(0, Math.min(scrollTrack.height - height, scrollTrack.height * fileListView.visibleArea.yPosition))
                                anchors.horizontalCenter: parent.horizontalCenter
                                radius: 1
                                color: "#ffb400"
                                opacity: 0.6
                            }
                        }
                            
                            Text {
                                anchors.centerIn: parent
                                text: "No files selected\nWaiting for input..."
                                color: "#666666"
                                font.pixelSize: 12
                                visible: fileListView.count === 0
                                horizontalAlignment: Text.AlignHCenter
                            }
                        }
                    }
                }

            // Password Section
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 8
                
                Text {
                    text: "PASSWORD"
                    color: "#666666"
                    font.pixelSize: 12
                    font.bold: true
                    font.letterSpacing: 1
                }
                
                ColumnLayout {
                    spacing: 4
                    Layout.bottomMargin: 4
                    
                    Repeater {
                        model: [
                            { label: "At least 16 characters", met: backend.hasMinLength },
                            { label: "2x Uppercase letters", met: backend.hasUppercase },
                            { label: "2x Lowercase letters", met: backend.hasLowercase },
                            { label: "2x Digits", met: backend.hasDigit },
                            { label: "2x Special characters", met: backend.hasSymbol }
                        ]
                        
                        delegate: RowLayout {
                            spacing: 8
                            Rectangle {
                                width: 6
                                height: 6
                                radius: 3
                                color: modelData.met ? "#00FF9D" : "#444444"
                                Behavior on color { ColorAnimation { duration: 200 } }
                            }
                            Text {
                                text: modelData.label
                                color: modelData.met ? "#FFFFFF" : "#666666"
                                font.pixelSize: 10
                                Behavior on color { ColorAnimation { duration: 200 } }
                            }
                        }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    height: 48
                    color: "#121416" // Card
                    border.color: "#1b1f21" // Secondary/Border
                    radius: 4
                    
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 12
                        anchors.rightMargin: 8
                        spacing: 8
                        
                        TextInput {
                            id: passwordInput
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            text: backend.password
                            onTextChanged: backend.password = text
                            echoMode: showPasswordBtn.checked ? TextInput.Normal : TextInput.Password
                            color: "#FFFFFF"
                            font.pixelSize: 14
                            selectionColor: "#ffb400"
                            verticalAlignment: TextInput.AlignVCenter
                            
                            Text {
                                text: "Enter secure password..."
                                color: "#444444"
                                visible: !parent.text && !parent.activeFocus
                                anchors.verticalCenter: parent.verticalCenter
                            }
                        }
                        
                        Button {
                            id: showPasswordBtn
                            Layout.preferredWidth: 32
                            Layout.preferredHeight: 32
                            Layout.alignment: Qt.AlignVCenter
                            padding: 0
                            checkable: true
                            flat: true
                            background: Item {}
                            
                            contentItem: Item {
                                implicitWidth: 32
                                implicitHeight: 32
                                
                                Image {
                                    id: openEye
                                    source: "qrc:/eye_open.svg"
                                    anchors.centerIn: parent
                                    width: 20
                                    height: 20
                                    opacity: showPasswordBtn.checked ? 1 : 0
                                    scale: showPasswordBtn.checked ? 1 : 0.8
                                    antialiasing: true
                                    Behavior on opacity { NumberAnimation { duration: 200 } }
                                    Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack } }
                                }
                                Image {
                                    id: closedEye
                                    source: "qrc:/eye_closed.svg"
                                    anchors.centerIn: parent
                                    width: 20
                                    height: 20
                                    opacity: showPasswordBtn.checked ? 0 : 1
                                    scale: showPasswordBtn.checked ? 0.8 : 1
                                    antialiasing: true
                                    Behavior on opacity { NumberAnimation { duration: 200 } }
                                    Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack } }
                                }
                            }
                        }
                    }
                }
                
                // Password Strength Bar (Simple line)
                Rectangle {
                    Layout.fillWidth: true
                    height: 2.5
                    color: "#333333"
                    
                    Rectangle {
                        width: parent.width * (backend.passwordStrength / 100)
                        height: parent.height
                        Behavior on width { NumberAnimation { duration: 200 } }
                        color: {
                            if (backend.passwordStrength < 40) return "#FF0055"
                            if (backend.passwordStrength < 100) return "#FFAA00"
                            return "#00FF9D"
                        }
                    }
                }
            }

            // Options Section
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 8
                
                Text {
                    text: "OPTIONS"
                    color: "#666666"
                    font.pixelSize: 12
                    font.bold: true
                    font.letterSpacing: 1
                }
                
                RowLayout {
                    Layout.fillWidth: true
                    
                    Text {
                        text: "Compression"
                        color: "#CCCCCC"
                        font.pixelSize: 14
                    }
                                        // Custom Compression Menu
                        Rectangle {
                            id: compressionSelector
                            Layout.preferredWidth: 180
                            Layout.preferredHeight: 44
                            Layout.alignment: Qt.AlignVCenter
                            color: "#16191b"
                            border.color: mouseArea.containsMouse ? "#333333" : "#2a2e30"
                            border.width: 1
                            radius: 8
                            
                            Behavior on border.color { ColorAnimation { duration: 150 } }
                            
                            property var options: ["None", "Balanced", "Maximum", "Ultra"]
                            property var values: [0, 2, 3, 4]
                            
                            function getLabel(val) {
                                for(var i=0; i<values.length; i++) {
                                    if(values[i] === val) return options[i];
                                }
                                return "None";
                            }

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 12
                                anchors.rightMargin: 12
                                spacing: 8
                                
                                Text {
                                    text: compressionSelector.getLabel(backend.compression)
                                    color: "#FFFFFF"
                                    font.pixelSize: 14
                                    font.bold: true
                                    Layout.fillWidth: true
                                    verticalAlignment: Text.AlignVCenter
                                    elide: Text.ElideRight
                                }
                                
                                Text {
                                    text: "▼"
                                    color: "#666666"
                                    font.pixelSize: 10
                                    rotation: compressionMenu.opened ? 180 : 0
                                    Behavior on rotation { NumberAnimation { duration: 200 } }
                                }
                            }
                            
                            MouseArea {
                                id: mouseArea
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                hoverEnabled: true
                                onClicked: compressionMenu.open()
                            }
                            
                            CompressionMenu {
                                id: compressionMenu
                                y: parent.height + 6
                                width: 240
                            }
                        }                  
                    Item { Layout.fillWidth: true }
                    
                    ColumnLayout {
                        CheckBox {
                            text: "Debug Mode"
                            checked: backend.verbose
                            onCheckedChanged: backend.verbose = checked
                            
                            contentItem: Text {
                                text: parent.text
                                color: "#CCCCCC"
                                leftPadding: parent.indicator.width + 4
                                verticalAlignment: Text.AlignVCenter
                            }
                        }
                        CheckBox {
                            text: "Secure Delete Original"
                            checked: backend.secureDelete
                            onCheckedChanged: backend.secureDelete = checked
                            
                            contentItem: Text {
                                text: parent.text
                                color: "#CCCCCC"
                                leftPadding: parent.indicator.width + 4
                                verticalAlignment: Text.AlignVCenter
                            }
                        }
                    }
                }
            }

            // Action Buttons
            RowLayout {
                Layout.fillWidth: true
                spacing: 16
                
                CustomButton {
                    text: "ENCRYPT"
                    Layout.fillWidth: true
                    Layout.preferredHeight: 48
                    isPrimary: true
                    onClicked: backend.encrypt()
                    enabled: !backend.isEncrypting
                }
                
                CustomButton {
                    text: "DECRYPT"
                    Layout.fillWidth: true
                    Layout.preferredHeight: 48
                    isPrimary: false
                    textColor: "#ffb400"
                    onClicked: backend.decrypt()
                    enabled: !backend.isEncrypting
                }
            }
            
            // Status Indicator
            RowLayout {
                Layout.fillWidth: true
                spacing: 6
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: 8
                    height: 8
                    radius: 4
                    color: backend.isEncrypting ? "#ffb400" : "#00FF9D"
                    Layout.alignment: Qt.AlignVCenter
                }
                Text {
                    text: backend.isEncrypting ? "BUSY" : "READY"
                    color: "#666666"
                    font.pixelSize: 10
                    font.bold: true
                    Layout.alignment: Qt.AlignVCenter
                }
                Text {
                    text: "• " + (backend.statusMessage === "READY" ? "idle" : (backend.statusMessage || "idle"))
                    color: "#666666"
                    font.pixelSize: 10
                    Layout.alignment: Qt.AlignVCenter
                }
            }

            Item { Layout.fillHeight: true } // Spacer

            // Runtime Telemetry
            Rectangle {
                Layout.fillWidth: true
                height: 100
                color: "#121416" // Card
                radius: 8
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 12
                    
                    RowLayout {
                        Layout.fillWidth: true
                        Text {
                            text: "RUNTIME TELEMETRY"
                            color: "#888888"
                            font.pixelSize: 12
                            font.bold: true
                            font.letterSpacing: 1
                        }
                        Item { Layout.fillWidth: true }

                    }
                    
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 12
                        
                        // Telemetry Box 1
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: "#0f1113"
                            radius: 4
                            Column {
                                anchors.centerIn: parent
                                Text { text: "Entropy Quality (8 is Perfection)"; color: "#666666"; font.pixelSize: 10 }
                                Text { text: backend.telemetryEntropy; color: "#FFFFFF"; font.family: "Monospace"; font.pixelSize: 12 }
                            }
                        }
                        // Telemetry Box 2
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: "#0f1113"
                            radius: 4
                            Column {
                                anchors.centerIn: parent
                                Text { text: "Processing Speed"; color: "#666666"; font.pixelSize: 10 }
                                Text { text: backend.telemetryThroughput; color: "#FFFFFF"; font.family: "Monospace"; font.pixelSize: 12 }
                            }
                        }
                        // Telemetry Box 3
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: "#0f1113"
                            radius: 4
                            Column {
                                anchors.centerIn: parent
                                Text { text: "Queue"; color: "#666666"; font.pixelSize: 10 }
                                Text { text: backend.telemetryQueue + " files"; color: "#FFFFFF"; font.family: "Monospace"; font.pixelSize: 12 }
                            }
                        }
                    }
                }
            }
        }
    FileDialog {
        id: fileDialog
        title: "Please choose a file"
        fileMode: FileDialog.OpenFiles
        onAccepted: {
            backend.addFiles(selectedFiles)
        }
    }
}
