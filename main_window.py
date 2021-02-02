# -*- coding: utf-8 -*-

from PyQt4 import QtCore, QtGui

import dataBrowser
import commandBrowser

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)


class myQPlainTextEdit(QtGui.QPlainTextEdit):
    def __init__(self, parent=None):
        super(myQPlainTextEdit, self).__init__(parent)
        self.save_shortcut = QtGui.QShortcut(QtGui.QKeySequence('Ctrl+S'), self)
        self.save_shortcut.setContext(QtCore.Qt.WidgetShortcut)
        self.save_shortcut.activated.connect(self.save_shortcut_activated)
        self.plainTextMode = True
        self.text_changed = False
        try:
            with open('sendDailog.txt', 'rb') as fd:
                val = fd.read().decode('gbk').replace('\r\n', '\n')
        except:
            val = ''
        val_split =  val.split('\n')
        if val_split[0] == 'MixDataMode':
            self.plainTextMode = False
            val = val.replace('MixDataMode\n', '', 1)
        self.setPlainText(val)
        self.textChanged.connect(self.text_changed_handler)

    def setPlainTextMode(self, mode):
        if self.plainTextMode != mode:
            self.plainTextMode = mode
            self.text_changed = True

    @QtCore.pyqtSlot()
    def save_shortcut_activated(self):
        if not self.text_changed: return
        self.text_changed = False
        with open('sendDailog.txt', 'wb') as fd:
            val = unicode(self.toPlainText())
            if not self.plainTextMode:
                val = 'MixDataMode\n' + val
            val = val.encode('gbk').replace('\n', '\r\n')
            ##print val
            fd.write(val)

    @QtCore.pyqtSlot()
    def text_changed_handler(self):
        ##print 'text_changed_handler'
        self.text_changed = True


class Ui_MainWindow(object):
    def setupUi(self, MainWindow, main_module):
        self.MainWindow = MainWindow
        self.main_module = main_module
        self.MainWindow_message = dataBrowser.msgSignal(MainWindow)

        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(1024, 800)
        MainWindow.setWindowIcon(QtGui.QIcon('./resource/SerialPort24.png'))
        ##icon = QtGui.QIcon()
        ##icon.addPixmap(QtGui.QPixmap('./resource/link-one.png'), QtGui.QIcon.Normal, QtGui.QIcon.On)
        ##MainWindow.setWindowIcon(icon)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setEnabled(True)

        self.mainSplitter = QtGui.QSplitter(QtCore.Qt.Horizontal, self.centralwidget)
        self.mainSplitter.setHandleWidth(1)

        self.leftSplitter = QtGui.QSplitter(QtCore.Qt.Vertical, self.mainSplitter)
        self.leftSplitter.setHandleWidth(1)

        # 左上
        ##self.dataBrowser = QtGui.QPlainTextEdit(self.leftSplitter)
        self.dataBrowserTab = QtGui.QTabWidget(self.leftSplitter)
        self.dataBrowserTab.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.dataBrowserTab.setTabsClosable(True)

        # 左下
        self.sendFrame = QtGui.QFrame(self.leftSplitter)
        self.sendFrame.setFrameShape(QtGui.QFrame.NoFrame)
        self.sendFrame.setFrameShadow(QtGui.QFrame.Plain)
        ##self.sendFrame.setFixedHeight(120)
        self.sendFrame.setMinimumHeight(140)
        qhboxlayout = QtGui.QHBoxLayout(self.sendFrame)
        qhboxlayout.setContentsMargins(5, 5, 5, 5)
        ##self.sendText = QtGui.QPlainTextEdit(self.sendFrame)
        self.sendText = myQPlainTextEdit(self.sendFrame)
        qhboxlayout.addWidget(self.sendText)
        qhboxlayout.addSpacing(15)

        qvboxlayout = QtGui.QVBoxLayout()
        qvboxlayout.setContentsMargins(0, 0, 0, 0)
        qvboxlayout.setSpacing(1)
        qvboxlayout.addSpacing(10)
        self.pushbutton_send = QtGui.QPushButton(u'发送', self.sendFrame)
        self.pushbutton_send.setFixedWidth(100)
        qvboxlayout.addWidget(self.pushbutton_send)
        self.data_sending = False

        self.radiobutton_plain = QtGui.QRadioButton(u'简单字符串', self.sendFrame)
        qvboxlayout.addWidget(self.radiobutton_plain)
        self.radiobutton_mix = QtGui.QRadioButton(u'组合字符串', self.sendFrame)
        ##self.radiobutton_plain.setChecked(True)
        if self.sendText.plainTextMode:
            self.radiobutton_plain.setChecked(True)
        else:
            self.radiobutton_mix.setChecked(True)
        qvboxlayout.addWidget(self.radiobutton_mix)
        qvboxlayout.addSpacing(10)

        qhboxlayout.addLayout(qvboxlayout)
        qhboxlayout.addSpacing(20)
        self.sendFrame.setLayout(qhboxlayout)

        # 右
        ##self.commandBrowser = QtGui.QPlainTextEdit(self.mainSplitter)
        self.commandBrowserTab = QtGui.QTabWidget(self.mainSplitter)
        self.commandBrowserTab.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.commandBrowserTab.setTabsClosable(True)
        ##self.commandBrowser = QtGui.QPlainTextEdit(self.commandBrowserTab)
        self.commandBrowser = commandBrowser.commandBrowser(self.commandBrowserTab, self, self.main_module, 'commands.txt')
        self.commandBrowserTab.addTab(self.commandBrowser, 'commands.txt')

        self.leftSplitter.setSizes([700, 100])
        self.mainSplitter.setSizes([700, 300])

        MainWindow.setCentralWidget(self.mainSplitter)

        ##self.menubar = QtGui.QMenuBar(MainWindow)
        ##self.menubar.setGeometry(QtCore.QRect(0, 0, 963, 20))
        ##MainWindow.setMenuBar(self.menubar)
        self.statusBar = QtGui.QStatusBar(MainWindow)
        MainWindow.setStatusBar(self.statusBar)
        self.statusBar.setFixedHeight(30)
        self.statusBar_connect_status = QtGui.QLabel(self.statusBar)
        self.statusBar_connect_status.setAlignment(QtCore.Qt.AlignCenter)
        self.statusBar.addWidget(self.statusBar_connect_status, 1)
        self.statusBar_rs_count = QtGui.QLabel(self.statusBar)
        self.statusBar_rs_count.setAlignment(QtCore.Qt.AlignCenter)
        self.statusBar.addWidget(self.statusBar_rs_count, 2)
        self.statusBar_code = QtGui.QLabel(self.statusBar)
        self.statusBar_code.setAlignment(QtCore.Qt.AlignCenter)
        self.statusBar.addWidget(self.statusBar_code, 1)

        # toolbar
        self.toolBar = QtGui.QToolBar(MainWindow)
        self.toolBar.setMovable(False)
        self.toolBar.setIconSize(QtCore.QSize(24, 24))
        MainWindow.addToolBar(self.toolBar)

        self.toolBar.addSeparator()
        self.toolBar.addSeparator()
        self.connectAction = QtGui.QAction(QtGui.QIcon('./resource/link-one.png'), 'Connect', self.toolBar)
        ##self.connectAction = QtGui.QAction('C', self.toolBar)
        self.toolBar.addAction(self.connectAction)
        self.disconnectAction = QtGui.QAction(QtGui.QIcon('./resource/unlink.png'), 'Disconnect', self.toolBar)
        ##self.disconnectAction = QtGui.QAction('D', self.toolBar)
        self.toolBar.addAction(self.disconnectAction)

        self.toolBar.addSeparator()
        self.toolBar.addSeparator()
        self.connect_combobox = QtGui.QComboBox(self.toolBar)
        self.connect_combobox.setFixedHeight(24)
        self.connect_combobox.setFixedWidth(300)
        self.connect_combobox.setEditable(True)
        self.connect_combobox.setFrame(True)
        self.connect_combobox.setInsertPolicy(QtGui.QComboBox.NoInsert)
        self.toolBar.addWidget(self.connect_combobox)
        self.display_add = QtGui.QAction('+', self.toolBar)
        self.display_add.setToolTip('Add')
        self.toolBar.addAction(self.display_add)

        self.toolBar.addSeparator()
        self.toolBar.addSeparator()
        self.display_mode_C = QtGui.QAction('C', self.toolBar)
        self.display_mode_C.setCheckable(True)
        self.display_mode_C.setChecked(True)
        self.display_mode_C.setToolTip('Char')
        self.toolBar.addAction(self.display_mode_C)
        self.display_mode_H = QtGui.QAction('H', self.toolBar)
        self.display_mode_H.setCheckable(True)
        self.display_mode_H.setToolTip('Hex')
        self.toolBar.addAction(self.display_mode_H)
        self.display_mode_T = QtGui.QAction('T', self.toolBar)
        self.display_mode_T.setCheckable(True)
        self.display_mode_T.setToolTip('Time')
        self.toolBar.addAction(self.display_mode_T)
        self.display_mode_E = QtGui.QAction('E', self.toolBar)
        self.display_mode_E.setCheckable(True)
        self.display_mode_E.setToolTip('Echo')
        self.toolBar.addAction(self.display_mode_E)
        self.display_mode_L = QtGui.QAction('L', self.toolBar)
        self.display_mode_L.setCheckable(True)
        self.display_mode_L.setToolTip('Log')
        self.toolBar.addAction(self.display_mode_L)
        self.display_mode_W = QtGui.QAction('W', self.toolBar)
        self.display_mode_W.setCheckable(True)
        self.display_mode_W.setToolTip('Wrap')
        self.toolBar.addAction(self.display_mode_W)

        self.toolBar.addSeparator()
        self.toolBar.addSeparator()
        self.display_clear = QtGui.QAction('Clear', self.toolBar)
        self.toolBar.addAction(self.display_clear)

        self.toolBar.addSeparator()
        self.toolBar.addSeparator()
        self.counter_reset = QtGui.QAction('Reset', self.toolBar)
        self.toolBar.addAction(self.counter_reset)

        self.toolBar.addSeparator()
        self.toolBar.addSeparator()
        self.commandBrowser_edit_mode = QtGui.QAction('Edit', self.toolBar)
        self.commandBrowser_edit_mode.setCheckable(True)
        self.toolBar.addAction(self.commandBrowser_edit_mode)

        self.MainWindow_message.signal_msg.connect(self.MainWindow_message_handler)

        self.dataBrowserTab.currentChanged.connect(self.dataBrowserTab_currentChanged)
        self.dataBrowserTab.tabCloseRequested.connect(self.dataBrowserTab_CloseRequested)

        self.commandBrowserTab.currentChanged.connect(self.commandBrowserTab_currentChanged)
        self.commandBrowserTab.tabCloseRequested.connect(self.commandBrowserTab_CloseRequested)

        self.connectAction.triggered.connect(self.connect_triggered)
        self.disconnectAction.triggered.connect(self.disconnect_triggered)

        self.display_add.triggered.connect(self.display_add_triggered)

        self.display_mode_H.triggered.connect(self.display_mode_triggered)
        self.display_mode_C.triggered.connect(self.display_mode_triggered)
        self.display_mode_T.triggered.connect(self.display_mode_triggered)
        self.display_mode_E.triggered.connect(self.display_mode_triggered)
        self.display_mode_L.triggered.connect(self.display_mode_triggered)
        self.display_mode_W.triggered.connect(self.display_mode_triggered)

        self.pushbutton_send.clicked.connect(self.pushbutton_send_clicked)

        self.display_clear.triggered.connect(self.display_clear_triggered)
        self.counter_reset.triggered.connect(self.counter_reset_triggered)

        self.commandBrowser_edit_mode.triggered.connect(self.edit_mode_triggered)

        self.message_handler_switch = {
            'appendText':             self.tabWidget_message_handler,
            'appendIPText':           self.tabWidget_message_handler,
            'appendEchoText':         self.tabWidget_message_handler,
            'newLineText':            self.tabWidget_message_handler,
            'dataChannelMsg':         self.tabWidget_message_handler,
            'closeEvent':             self.closeEvent_message_handler,
            'sendPlainData':          self.sendData_message_handler,
            'sendMixData':            self.sendData_message_handler,
            'displayClear':           self.displayClear_message_handler,
            'counterReset':           self.counterReset_message_handler,
            'statusChange':           self.status_message_handler,
            'statusBarFlashText':     self.statusBarFlashText_message_handler,
            'newCommandTab':          self.newCommandTab_message_handler,
            'newDataBrowserTab':      self.newDataBrowserTab_message_handler,
            'remoteDataBrowserTab':   self.remoteDataBrowserTab_message_handler,
            'acceptedDataBrowserTab': self.acceptedDataBrowserTab_message_handler,
            'setCode':                self.setCode_message_handler,
        }

        ##link_strs = ['192.168.0.11:7788', 'u:192.168.0.11:7788']
        ##for link_str in link_strs:
        ##    self.connect_combobox.addItem(link_str, link_str)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow", None))

    def counterReset_message_handler(self, msg_type, msg_data):
        if msg_type: pass
        if msg_data: pass
        tabWidget = self.dataBrowserTab.currentWidget()
        if tabWidget: tabWidget.counter_reset()

    def displayClear_message_handler(self, msg_type, msg_data):
        if msg_type: pass
        if msg_data: pass
        tabWidget = self.dataBrowserTab.currentWidget()
        if tabWidget: tabWidget.display_clear()

    def sendData_message_handler(self, msg_type, msg_data):
        tabWidget = self.dataBrowserTab.currentWidget()
        if tabWidget: tabWidget.send_data(msg_type, msg_data)

    def tabWidget_message_handler(self, msg_type, msg_data):
        tabWidget, tabWidget_msg = msg_data
        tabWidget.msg_handler(msg_type, tabWidget_msg)

    def closeEvent_message_handler(self, msg_type, msg_data):
        ##print 'closeEvent_message_handler'
        if msg_type: pass
        if msg_data: pass
        for i in range(self.dataBrowserTab.count()):
            tabWidget = self.dataBrowserTab.widget(i)
            tabWidget.stop_link()

    def status_message_handler(self, msg_type, msg_data):
        if msg_type: pass
        tabWidget = msg_data
        if tabWidget is self.dataBrowserTab.currentWidget():
            self.reflash_status_indecate()
        else:
            i = self.dataBrowserTab.indexOf(tabWidget)
            self.dataBrowserTab.setTabText(i, '*' + tabWidget.head_str)

    def statusBarFlashText_message_handler(self, msg_type, msg_data):
        if msg_type: pass
        self.statusBar.showMessage(msg_data, 2000)

    def newCommandTab_message_handler(self, msg_type, msg_data):
        if msg_type: pass
        for i in range(self.commandBrowserTab.count()):
            tabWidget = self.commandBrowserTab.widget(i)
            if tabWidget.file_path == msg_data:
                self.commandBrowserTab.setCurrentIndex(i)
                return
        command_Browser = commandBrowser.commandBrowser(self.commandBrowserTab, self, self.main_module, msg_data)
        self.commandBrowserTab.addTab(command_Browser, command_Browser.file_name)
        self.commandBrowserTab.setCurrentWidget(command_Browser)

    def newDataBrowserTab_message_handler(self, msg_type, msg_data):
        if msg_type: pass
        for i in range(self.dataBrowserTab.count()):
            tabWidget = self.dataBrowserTab.widget(i)
            if tabWidget.compare_linkStr(msg_data):
                self.dataBrowserTab.setCurrentIndex(i)
                self.reflash_status_indecate()
                return
        data_Browser = dataBrowser.dataBrowser(self.dataBrowserTab, self, self.main_module, msg_data)
        self.dataBrowserTab.addTab(data_Browser, data_Browser.head_str)
        self.dataBrowserTab.setCurrentWidget(data_Browser)
        ##self.reflash_status_indecate()
        data_Browser.start_link()

    def remoteDataBrowserTab_message_handler(self, msg_type, msg_data):
        if msg_type: pass
        data_Browser = msg_data
        self.dataBrowserTab.addTab(data_Browser, data_Browser.head_str)

    def acceptedDataBrowserTab_message_handler(self, msg_type, msg_data):
        if msg_type: pass
        linkStr, remote_socket, remote_address, listen_DataBrowser = msg_data
        data_Browser = dataBrowser.dataBrowser(self.dataBrowserTab, self, self.main_module, linkStr,
                                               remote_socket,
                                               remote_address,
                                               listen_DataBrowser)
        self.dataBrowserTab.addTab(data_Browser, data_Browser.head_str)
        data_Browser.start_link()

    def setCode_message_handler(self, msg_type, msg_data):
        if msg_type: pass
        tabWidget = self.dataBrowserTab.currentWidget()
        if tabWidget:
            tabWidget.dataChannelcode = msg_data
            self.statusBar_code.setText(tabWidget.dataChannelcode.upper())

    def get_toolbar_display_mode(self):
        display_mode = ''
        if self.display_mode_H.isChecked(): display_mode += 'H'
        if self.display_mode_C.isChecked(): display_mode += 'C'
        if self.display_mode_T.isChecked(): display_mode += 'T'
        if self.display_mode_E.isChecked(): display_mode += 'E'
        if self.display_mode_L.isChecked(): display_mode += 'L'
        if self.display_mode_W.isChecked(): display_mode += 'W'
        return display_mode

    def set_toolbar_display_mode(self, display_mode):
        if 'H' in display_mode: self.display_mode_H.setChecked(True)
        else: self.display_mode_H.setChecked(False)
        if 'C' in display_mode: self.display_mode_C.setChecked(True)
        else: self.display_mode_C.setChecked(False)
        if 'T' in display_mode: self.display_mode_T.setChecked(True)
        else: self.display_mode_T.setChecked(False)
        if 'E' in display_mode: self.display_mode_E.setChecked(True)
        else: self.display_mode_E.setChecked(False)
        if 'L' in display_mode: self.display_mode_L.setChecked(True)
        else: self.display_mode_L.setChecked(False)
        if 'W' in display_mode: self.display_mode_W.setChecked(True)
        else: self.display_mode_W.setChecked(False)

    def reflash_status_indecate(self):
        tabWidget = self.dataBrowserTab.currentWidget()
        if not tabWidget:
            self.statusBar_connect_status.setText('')
            self.statusBar_rs_count.setText('')
            self.statusBar_code.setText('')
            if self.data_sending:
                self.pushbutton_send.setText(u'发送')
                self.data_sending = False
            return

        if tabWidget.dataChannel:
            if self.data_sending and not tabWidget.dataChannel.data_sending:
                self.pushbutton_send.setText(u'发送')
            elif tabWidget.dataChannel.data_sending and not self.data_sending:
                self.pushbutton_send.setText(u'停止发送')
            self.data_sending = tabWidget.dataChannel.data_sending

        if self.get_toolbar_display_mode() != tabWidget.display_mode:
            self.set_toolbar_display_mode(tabWidget.display_mode)

        self.statusBar_connect_status.setText(tabWidget.get_status())
        counts_str = u'接收: %-8d 发送: %-8d' % (tabWidget.recv_counts, tabWidget.send_counts)
        self.statusBar_rs_count.setText(counts_str)
        self.statusBar_code.setText(tabWidget.dataChannelcode.upper())

    @QtCore.pyqtSlot()
    def MainWindow_message_handler(self, msg_type, msg_data):
        ##print 'MainWindow_message_handler', repr(msg_type)
        msg_type = str(msg_type)
        if self.message_handler_switch.has_key(msg_type):
            self.message_handler_switch[msg_type](msg_type, msg_data)

    @QtCore.pyqtSlot()
    def dataBrowserTab_currentChanged(self, index):
        print 'dataBrowserTab_currentChanged', index
        if index >= 0:
            tabWidget = self.dataBrowserTab.widget(index)
            self.dataBrowserTab.setTabText(index, tabWidget.head_str)
        self.reflash_status_indecate()

    @QtCore.pyqtSlot()
    def dataBrowserTab_CloseRequested(self, index):
        print 'close dataBrowserTab', index
        tabWidget = self.dataBrowserTab.widget(index)
        tabWidget.stop_link()
        tabWidget.close()
        self.dataBrowserTab.removeTab(index)

    @QtCore.pyqtSlot()
    def commandBrowserTab_currentChanged(self, index):
        print 'commandBrowserTab_currentChanged', index
        tabWidget = self.commandBrowserTab.widget(index)
        self.commandBrowser_edit_mode.setChecked(tabWidget.edit_mode)

    @QtCore.pyqtSlot()
    def commandBrowserTab_CloseRequested(self, index):
        if index == 0: return
        print 'close commandBrowserTab', index
        ##tabWidget = self.commandBrowserTab.widget(index)
        self.commandBrowserTab.removeTab(index)
        ##tabWidget.destroy()

    @QtCore.pyqtSlot()
    def display_add_triggered(self):
        link_str = unicode(self.connect_combobox.currentText())
        if link_str == '' or link_str == None or len(link_str) < 4:
            return
        if self.connect_combobox.findData(link_str) == -1 :
            self.connect_combobox.insertItem(0, link_str, link_str)
        self.MainWindow_message.signal_msg.emit('newDataBrowserTab', link_str)

    @QtCore.pyqtSlot()
    def display_mode_triggered(self):
        ##print 'display_mode_triggered'
        if not self.display_mode_H.isChecked() and not self.display_mode_C.isChecked():
            self.display_mode_C.setChecked(True)
        tabWidget = self.dataBrowserTab.currentWidget()
        if tabWidget:
            tabWidget.set_display_mode(self.get_toolbar_display_mode())

    @QtCore.pyqtSlot()
    def connect_triggered(self):
        tabWidget = self.dataBrowserTab.currentWidget()
        if tabWidget:
            tabWidget.start_link()

    @QtCore.pyqtSlot()
    def disconnect_triggered(self):
        tabWidget = self.dataBrowserTab.currentWidget()
        if tabWidget:
            tabWidget.stop_link()

    @QtCore.pyqtSlot()
    def pushbutton_send_clicked(self):
        self.sendText.save_shortcut_activated()

        tabWidget = self.dataBrowserTab.currentWidget()
        if not tabWidget: return

        if self.data_sending:
            tabWidget.stop_send_data()
            return

        data = unicode(self.sendText.toPlainText())
        self.data_sending = True
        self.pushbutton_send.setText(u'停止发送')
        if self.radiobutton_plain.isChecked():
            self.sendText.setPlainTextMode(True)
            data = data.replace('\n', '\r\n')
            ##self.MainWindow_message.signal_msg.emit('sendPlainData', data)
            tabWidget.send_data('sendPlainData', data)
        else:
            self.sendText.setPlainTextMode(False)
            data_split = data.split('\n')
            send_loop_end = False
            for data in data_split:
                ##self.MainWindow_message.signal_msg.emit('sendMixData', data)
                tabWidget.send_data('sendMixData', data)
                if len(data) >= 5 and data[0:5].upper() == 'LOOP:':
                    send_loop_end = not send_loop_end
            if send_loop_end:
                ##self.MainWindow_message.signal_msg.emit('sendMixData', 'LOOP:END')
                tabWidget.send_data('sendMixData', 'LOOP:END')

    @QtCore.pyqtSlot()
    def display_clear_triggered(self):
        self.MainWindow_message.signal_msg.emit('displayClear', None)

    @QtCore.pyqtSlot()
    def counter_reset_triggered(self):
        self.MainWindow_message.signal_msg.emit('counterReset', None)


    @QtCore.pyqtSlot()
    def edit_mode_triggered(self):
        tabWidget = self.commandBrowserTab.currentWidget()
        if tabWidget:
            tabWidget.set_edit_mode(self.commandBrowser_edit_mode.isChecked())
