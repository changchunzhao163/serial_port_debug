from PyQt4 import QtCore, QtGui
import dataBrowser


class commandBrowser(QtGui.QPlainTextEdit):
    def __init__(self, parent=None, MainWindow=None, main_module=None, file_name=None):
        super(commandBrowser, self).__init__(parent)
        self.parent = parent
        self.MainWindow = MainWindow
        self.main_module = main_module
        self.file_name = file_name
        self.edit_mode = False
        ##self.setReadOnly(True)
        self.setLineWrapMode(QtGui.QPlainTextEdit.NoWrap)
        self.save_shortcut = QtGui.QShortcut(QtGui.QKeySequence('Ctrl+S'), self)
        self.save_shortcut.setContext(QtCore.Qt.WidgetShortcut)
        self.save_shortcut.activated.connect(self.save_shortcut_activated)

        self.signal_msg = self.MainWindow.MainWindow_message.signal_msg
        self.cursorPositionChanged.connect(self.highligtCurrentLine)
        try:
            with open(self.file_name, 'rb') as fd:
                val = fd.read().decode('gbk').replace('\r\n', '\n')
        except:
            val = ''
        self.setPlainText(val)

    @QtCore.pyqtSlot()
    def highligtCurrentLine(self):
        selection = QtGui.QTextEdit.ExtraSelection()
        selection.format.setBackground(QtGui.QColor(QtCore.Qt.gray).lighter(130))
        selection.format.setProperty(QtGui.QTextFormat.FullWidthSelection, True)
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        ##extraSelection.clear()
        extraSelection = [selection]
        ##extraSelection.append(selection)
        self.setExtraSelections(extraSelection)

    @QtCore.pyqtSlot()
    def save_shortcut_activated(self):
        with open(self.file_name, 'wb') as fd:
            val = unicode(self.toPlainText()).encode('gbk').replace('\n', '\r\n')
            ##print val
            fd.write(val)

    def doubleClick_line(self):
        cursor = self.textCursor()
        lineNumber = cursor.blockNumber()
        textDocument = self.document()
        textBlock = textDocument.findBlockByLineNumber(lineNumber)
        try:
            selectLine = unicode(textBlock.text())
            if len(selectLine) == 0: return
            if selectLine[0:1] == '#': return
            msg_type = 'sendPlainData'
            msg_data = selectLine + '\r\n'
            if len(selectLine) > 2:
                mix_command = selectLine.split(':')[0].upper()
                if mix_command in ['M', 'S', 'LOOP']:
                    msg_type = 'sendMixData'
                    msg_data = selectLine
                elif mix_command == 'F':
                    msg_type = 'newCommandTab'
                    msg_data = selectLine[2:]
                elif mix_command in dataBrowser.mode_str_to_mode \
                        and mix_command != 'AT' and mix_command != 'AU':
                    msg_type = 'newDataBrowserTab'
                    msg_data = selectLine
            self.signal_msg.emit(msg_type, msg_data)
        except:
            pass

    def mouseDoubleClickEvent(self, event):
        if not self.edit_mode:
            self.doubleClick_line()
            event.ignore()
        else:
            super(commandBrowser, self).mouseDoubleClickEvent(event)

    def set_edit_mode(self, mode):
        self.edit_mode = mode
        if mode:
            ##self.setReadOnly(False)
            pass
        else:
            ##self.setReadOnly(True)
            self.save_shortcut_activated()
