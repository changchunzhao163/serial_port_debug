# -*- coding: utf-8 -*-

from PyQt4 import QtCore, QtGui
import sys
import Queue
import threading
import time
import socket

import main_window

main_window_msg = None
getHostByName_queue = None
hostName2IP = dict()


class myQMainWindow(QtGui.QMainWindow):
    def __init__(self):
        super(myQMainWindow, self).__init__()

    def closeEvent(self, event):
        print 'closeEvent'
        main_window_msg.emit('closeEvent', ())
        event.accept()


def getHostByName_thread(host):
    print 'getHostByName_thread', host
    try:
        ip_str = socket.gethostbyname(host)
        if ip_str:
            getHostByName_queue.put(('ADD', (host, ip_str)))
    except Exception as e:
        print 'getHostByName_thread Exception', e

def getHostByName_main_thread():
    global getHostByName_queue
    while True:
        try:
            req, req_data = getHostByName_queue.get(True)
        except:
            continue

        if req == 'EXIT':
            print 'getHostByName_main_thread EXIT'
            break
        elif req == 'REQUEST':
            threading.Thread(target=getHostByName_thread, name='getHostByName_thread', args=(req_data,)).start()
        elif req == 'ADD':
            host, ip_str = req_data
            hostName2IP[host] = (ip_str, time.time())
        elif req == 'DELETE':
            try: del hostName2IP[req_data]
            except: pass

def getHostByName_request(host):
    global hostName2IP
    global getHostByName_queue
    if host in hostName2IP:
        ip_str, timestamp = hostName2IP[host]
        if time.time() - timestamp < 10:
            return ip_str
    getHostByName_queue.put(('REQUEST', host))
    return ''

def getHostByName_result(host):
    global hostName2IP
    if host in hostName2IP:
        ip_str, timestamp = hostName2IP[host]
        if time.time() - timestamp < 10:
            getHostByName_queue.put(('DELETE', host))
            return ip_str
    return ''

def main() :
    global main_window_msg
    global getHostByName_queue

    print sys.getdefaultencoding()
    ##reload(sys)
    ##sys.setdefaultencoding('utf8')

    getHostByName_queue = Queue.Queue(64)
    threading.Thread(target=getHostByName_main_thread, name='getHostByName_main_thread').start()

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

    getHostByName_queue.put(('EXIT', ''))

if __name__ == '__main__':
    main()