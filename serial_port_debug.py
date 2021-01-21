# -*- coding: utf-8 -*-

from PyQt4 import QtCore, QtGui
import sys

import main_window

main_window_msg = None


class myQMainWindow(QtGui.QMainWindow):
    def __init__(self):
        super(myQMainWindow, self).__init__()

    def closeEvent(self, event):
        print 'closeEvent'
        main_window_msg.emit('closeEvent', ())
        event.accept()

def main() :
    global main_window_msg

    app=QtGui.QApplication(sys.argv)
    ##MainWindow = QtGui.QMainWindow()
    MainWindow = myQMainWindow()
    ##style_str = u'Plastique'
    styleFactory = QtGui.QStyleFactory()
    style = styleFactory.create(u'Plastique')
    app.setStyle(style)

    ui = main_window.Ui_MainWindow()
    ui.setupUi(MainWindow, sys.modules['__main__'])
    main_window_msg = ui.MainWindow_message.signal_msg
    MainWindow.show()

    app.exec_()

if __name__ == '__main__':
    main()