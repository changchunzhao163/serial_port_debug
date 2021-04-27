# -*- coding: utf-8 -*-

from PyQt4 import QtCore, QtGui
import dataBrowser

data_command_head = ['M', 'S', 'LOOP', 'SF']

def get_command_from_data(data):
    data_split = data.split(':')
    if len(data_split) > 1 and (len(data_split[1]) > 0 or len(data_split) > 2):
        return data_split[0].upper()
    return ''


class commandBrowser(QtGui.QPlainTextEdit):
    def __init__(self, parent=None, MainWindow=None, main_module=None, file_path=None):
        super(commandBrowser, self).__init__(parent)
        self.parent = parent
        self.MainWindow = MainWindow
        self.main_module = main_module
        self.file_path = file_path
        if '\\' in file_path: self.file_name = file_path.split('\\')[-1]
        elif '/' in file_path: self.file_name = file_path.split('/')[-1]
        else: self.file_name = file_path
        ##self.file_name = file_name
        ##self.edit_mode = False
        ##self.setReadOnly(True)
        self.setLineWrapMode(QtGui.QPlainTextEdit.NoWrap)
        self.save_shortcut = QtGui.QShortcut(QtGui.QKeySequence('Ctrl+S'), self)
        self.save_shortcut.setContext(QtCore.Qt.WidgetShortcut)
        self.save_shortcut.activated.connect(self.save_shortcut_activated)

        self.signal_msg = self.MainWindow.MainWindow_message.signal_msg
        self.cursorPositionChanged.connect(self.highligtCurrentLine)
        self.createContextMenu()
        self.text_changed = False
        self.org_code = ''
        try:
            with open(self.file_path, 'rb') as fd:
                file_contents = fd.read()
                try:
                    val = file_contents.decode('gbk').replace('\r\n', '\n')
                    self.org_code = 'gbk'
                except Exception as e:
                    print e
                    try:
                        val = file_contents.decode('utf-8').replace('\r\n', '\n')
                        self.org_code = 'utf-8'
                    except Exception as e:
                        print e
                        val = ''
                        self.signal_msg.emit('statusBarFlashText', u'文件 %s 解码错误' % self.file_name)
        except:
            val = ''
            self.org_code = 'gbk'
            if self.file_path == 'commands.txt':
                val = 'HELP::'
                ##self.text_changed = True
        self.setPlainText(val)
        self.textChanged.connect(self.text_changed_handler)

    def createContextMenu(self) :
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.showContextMenu)
        ##self.contextMenu = QtGui.QMenu(self)
        ##self.copy_Action = self.contextMenu.addAction('&Copy     Ctrl+C')
        ##self.copy_Action.triggered.connect(self.copy)
        ##self.paste_Action = self.contextMenu.addAction('&Paste    Ctrl+V')
        ##self.paste_Action.triggered.connect(self.paste)

    def showContextMenu(self, pos):
        if pos: pass

        self.contextMenu = QtGui.QMenu(self)

        self.copy_Action = self.contextMenu.addAction('&Copy      Ctrl+C')
        self.copy_Action.triggered.connect(self.copy)
        self.paste_Action = self.contextMenu.addAction('&Paste     Ctrl+V')
        self.paste_Action.triggered.connect(self.paste)
        self.contextMenu.addAction('').setSeparator(True)

        if len(self.textCursor().selectedText()) > 0:
            self.send_selected_Action = self.contextMenu.addAction(u'发送选中内容')
            self.send_selected_Action.triggered.connect(self.send_selected_handler)
        else:
            self.send_line_Action = self.contextMenu.addAction(u'发送当前行')
            self.send_line_Action.triggered.connect(self.doubleClick_line)

        self.contextMenu.move(self.cursor().pos())
        self.contextMenu.show()

    @QtCore.pyqtSlot()
    def text_changed_handler(self):
        if not self.text_changed:
            i = self.parent.indexOf(self)
            self.parent.setTabText(i, '*' + self.file_name)
        self.text_changed = True

    @QtCore.pyqtSlot()
    def send_selected_handler(self):
        ##selectedText = unicode(self.textCursor().selectedText()).encode('utf-8')
        ##selectedText = unicode(self.textCursor().selectedText(), 'utf-8', 'ignore')
        selectedText = unicode(self.textCursor().selectedText())
        selectedText_split = selectedText.split(u'\u2029')  # u'\u2029'段落分割符
        send_loop_end = False
        msg_type = 'sendMixData'
        for data in selectedText_split:
            if len(data) == 0 or data[0:1] == '#': continue
            mix_command = get_command_from_data(data)
            if mix_command == 'F' \
                    or mix_command == 'CODE'\
                    or mix_command in dataBrowser.mode_str_to_mode:
                continue
            if mix_command not in data_command_head:
                data = data + '\r\n'
            elif mix_command == 'LOOP':
                send_loop_end = not send_loop_end
            msg_data = data
            ##print selectedText
            self.signal_msg.emit(msg_type, msg_data)
        if send_loop_end:
            self.signal_msg.emit(msg_type, 'LOOP:END')

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
        if not self.text_changed: return
        if not self.org_code: return
        self.text_changed = False
        self.parent.setTabText(self.parent.indexOf(self), self.file_name)
        with open(self.file_path, 'wb') as fd:
            val = unicode(self.toPlainText()).encode(self.org_code).replace('\n', '\r\n')
            ##print val
            fd.write(val)

    def doubleClick_line(self):
        cursor = self.textCursor()
        blockNumber = cursor.blockNumber()
        textDocument = self.document()
        ##textBlock = textDocument.findBlockByLineNumber(lineNumber)
        textBlock = textDocument.findBlockByNumber(blockNumber)
        try:
            selectLine = unicode(textBlock.text())
            if len(selectLine) == 0: return
            if selectLine[0:1] == '#': return
            msg_type = 'sendPlainData'
            msg_data = selectLine + '\r\n'
            mix_command = get_command_from_data(selectLine)
            if mix_command != '':
                if mix_command in data_command_head:
                    msg_type = 'sendMixData'
                    msg_data = selectLine
                elif mix_command == 'F':
                    msg_type = 'newCommandTab'
                    msg_data = selectLine[2:]
                elif mix_command == 'CODE':
                    msg_type = 'setCode'
                    msg_data = selectLine[5:]
                elif mix_command in dataBrowser.mode_str_to_mode \
                        and mix_command != 'AT' and mix_command != 'AU':
                    msg_type = 'newDataBrowserTab'
                    msg_data = selectLine
            self.signal_msg.emit(msg_type, msg_data)
        except:
            pass

    def mouseDoubleClickEvent(self, event):
        ##if not self.edit_mode:
        if not self.text_changed:
            self.doubleClick_line()
            event.ignore()
        else:
            super(commandBrowser, self).mouseDoubleClickEvent(event)

    ##def set_edit_mode(self, mode):
    ##    self.edit_mode = mode
    ##    if mode:
    ##        ##self.setReadOnly(False)
    ##        pass
    ##    else:
    ##        ##self.setReadOnly(True)
    ##        self.save_shortcut_activated()
