# -*- coding: utf-8 -*-

from PyQt4 import QtCore, QtGui
import socket
import threading
import time
import datetime
import binascii
import Queue
import collections
import serial

def crc16_c(Tar, res=0xFFFF):
    # 查表法计算crc16值，利用给定的表格，计算目标字符串的crc值
    # CRC-16        多项式：x16+x15+x2+1            8005      IBM SDLC
    # 该函数可以计算8位或16位的crc值,res为计算初始值，默认为0xFFFF，可以为0x0000
    Table = [
        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
        0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
        0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
        0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
        0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
        0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
        0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
        0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
        0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
        0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
        0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
        0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
        0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
        0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
        0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
        0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
        0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040, ]
    if len(Table) != 256:
        print u"表格长度必须为256"
    loop1 = 0
    while loop1 < 256:
        if Table[loop1] < 0 or Table[loop1] > 65535:
            print u"表格内的数据必须为16位无符号数"
            return None
        loop1 += 1
    for b in Tar:
        if isinstance(b, str):
            b = ord(b)
        if not 0 <= b < 256:
            print u"目标元素必须为0－255之间的数"
            return None
        #该过程可以兼容16位和8位crc的操作，因为8位crc的表格高字节是0
        #异或以后不影响值。如果专门为8位编写，则可以更加简单，
        cb = res & 0xff
        cb ^= b
        #查表，如果只考虑8位crc，直接使用 res=Table[cb]即可
        cb = Table[cb]
        res >>= 8
        res ^= cb
    res = ((res << 8) & 0xff00) | ((res >> 8) & 0x00ff)
    return "%04X" % res
    ##return bytes(res)

mode_str_to_mode = {
    'T': 'tcp client',
    'AT': 'tcp accept client',
    'U': 'udp client',
    'AU': 'udp accept client',
    'TL': 'tcp listen',
    'UL': 'udp listen',
    'C': 'com',
}

uart_bytesize_set = {
    '8':serial.EIGHTBITS,
    '7':serial.SEVENBITS,
    '6':serial.SIXBITS,
    '5':serial.FIVEBITS,
}

uart_stopbits_set = {
    '1':serial.STOPBITS_ONE,
    '2':serial.STOPBITS_TWO,
    '3':serial.STOPBITS_ONE_POINT_FIVE,
}

uart_parity_set = {
    '0':serial.PARITY_NONE,
    '1':serial.PARITY_ODD,
    '2':serial.PARITY_EVEN,
    '3':serial.PARITY_SPACE,
}

socket_inprocess_errorno = ['10035', '10036', '10037', '10022']
def client_connect(s, addr):
    Errno = ''
    try:
        s.connect(addr)
        Errno = '0'
    except Exception as e:
        if '[Errno ' in str(e):
            Errno = str(e)[7:-2]
    ##print Errno
    if Errno == '0' or Errno == '10056':
        return 1
    elif Errno in socket_inprocess_errorno:
        return 0
    else:
        return -1


class SocketSerial(object):
    def __init__(self, s):
        self._socket = s
        self._socket.setblocking(True)
        self._socket.settimeout(0.01)

    def close(self):
        if self._socket is None: return
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
            self._socket = None
        except:
            pass

    def read(self, size=1):
        data = bytearray()
        try:
            data = self._socket.recv(size)
            if data == b'': raise Exception('connection failed')
        except socket.timeout:
            pass
        except:
            raise
        return bytes(data)

    def write(self, data):
        try:
            self._socket.sendall(data)
        except:
            raise


class msgSignal(QtCore.QObject):
    signal_msg = QtCore.pyqtSignal(str, object)
    ##signal_event = QtCore.pyqtSignal()
    def __init__(self, parent=None):
        super(msgSignal, self).__init__(parent)


class dataBrowser(QtGui.QPlainTextEdit):
    def __init__(self, parent=None, MainWindow=None, main_module=None, linkStr=None):
        super(dataBrowser, self).__init__(parent)
        self.parent = parent
        self.MainWindow = MainWindow
        self.main_module = main_module
        self.linkStr = linkStr
        self.socekt = None
        self.status = 'Idle'
        self.last_new_line = 2
        self.log_handler = None
        self.recv_counts = 0
        self.send_counts = 0
        self.send_queue_cache = collections.deque()
        self.send_thread_queue = Queue.Queue(200)
        self.send_thread_running = False
        self.mode, self.ip_str, self.port_str, self.display_mode = self.paser_linkStr(linkStr)
        print self.mode, self.ip_str, self.port_str, self.display_mode
        self.signal_msg = self.MainWindow.MainWindow_message.signal_msg
        self.setReadOnly(True)
        if 'L' in self.display_mode: self.start_log()

    def paser_linkStr(self, linkStr):
        # linkStr 格式, ':'号分割
        # 'T', 'AT', 'U', 'AU', 'TL', 'UL', ''
        # '192.168.0.11', 'COM5'
        # '7788', '810'
        # 'HCTEL'
        linkStr_split = linkStr.split(':')
        mode = 'tcp client'
        display_mode = 'C'  # 'HCTEL'
        port_str = '65500'
        if linkStr_split[0].upper() in mode_str_to_mode:
            mode = mode_str_to_mode[linkStr_split[0].upper()]
            del linkStr_split[0]
        if len(linkStr_split[0].split('.')) != 4:
            mode = 'com'
            port_str = '810'
        ip_str = linkStr_split[0].upper()
        if mode == 'com' and len(linkStr_split) > 1 and len(linkStr_split[1]) >= 4:
            ip_str += ':' + linkStr_split[1]
            del linkStr_split[1]
        if len(linkStr_split) > 1:
            if len(linkStr_split[1]) > 0: port_str = linkStr_split[1]
        if len(linkStr_split) > 2:
            if len(linkStr_split[2]) > 0: display_mode = linkStr_split[2]

        return mode, ip_str, port_str, display_mode

    def compare_linkStr(self, linkStr):
        mode, ip_str, port_str, display_mode = self.paser_linkStr(linkStr)
        if mode != self.mode: return False
        if ip_str != self.ip_str: return False
        if port_str != self.port_str: return False
        return True

    def genarat_display_str(self, disp_type, data):
        disp_str = ''
        if self.last_new_line == 0 and disp_type == 'appendEchoText':
            disp_str += '\n'
            self.last_new_line = 1
        if 'T' in self.display_mode:
            time_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            disp_str += '\n' * (2 - self.last_new_line)
            if disp_type == 'appendText':
                ##disp_str += '--- RECV ' + time_str + ' ---\n'
                disp_str += '[%s] RECV: %d bytes\n' % (time_str, len(data))
            else:
                ##disp_str += '--- SEND ' + time_str + ' ---\n'
                disp_str += '[%s] SEND: %d bytes\n' % (time_str, len(data))
        if 'H' in self.display_mode and 'C' in self.display_mode:
            bytes_data = bytes(data)
            str_data = ''
            i = 0
            for b in bytes_data:
                disp_str += '%02X ' % ord(b)
                i += 1
                if ord(b) < 0x20 or ord(b) > 0x7F:
                    str_data += '.'
                else:
                    str_data += b
                if i == 16:
                    i = 0
                    disp_str += ' ' * 8 + str_data + '\n'
                    str_data = ''
            if str_data:
                disp_str += ' ' * ((16 -i)*3) + ' ' * 8 + str_data + '\n'
        elif 'H' in self.display_mode:
            bytes_data = bytes(data)
            for b in bytes_data:
                disp_str += '%02X ' % ord(b)
        else: disp_str += data

        return disp_str

    @QtCore.pyqtSlot()
    def display_msg_handler(self, msq_type, msq_data):
        self.moveCursor(QtGui.QTextCursor.End)
        disp_str = ''
        if msq_type == 'appendText' or msq_type == 'appendEchoText':
            disp_str = self.genarat_display_str(msq_type, msq_data)
            if '\n' == disp_str[-1:]:
                self.last_new_line = 1
            else:
                if msq_type == 'appendEchoText':
                    disp_str += '\n'
                    self.last_new_line = 1
                else:
                    self.last_new_line = 0
        else:
            if msq_data:
                time_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                time_str = '--- ' + time_str + ' ---'
                disp_str += '\n' * (2 - self.last_new_line)
                disp_str += time_str + '\n' + msq_data + '\n'
            disp_str += '\n'
            self.last_new_line = 2
        self.insertPlainText(disp_str)
        self.moveCursor(QtGui.QTextCursor.End)
        if self.log_handler:
            try:
                self.log_handler.write(disp_str)
                self.log_handler.flush()
            except:
                self.log_handler = None

    def start_link(self):
        if self.socekt is not None: return
        if self.status != 'Idle': return
        ##self.recvThread.start()
        self.status = 'Connecting'
        self.signal_msg.emit('statusChange', self)
        threading.Thread(target=self.recv_thread, name='recv_thread').start()
        if not self.send_thread_running:
            self.send_thread_running = True
            threading.Thread(target=self.send_thread, name='send_thread').start()

    def stop_link(self):
        print 'stop_link'
        if self.send_thread_running:
            self.send_thread_queue.put(('EXIT', ''))
            self.send_thread_running = False
        if self.socekt is None: return
        try: self.socekt.close()
        except: pass
        self.socekt = None
        self.signal_msg.emit('newLineText', (self, 'disconnect.'))
        self.signal_msg.emit('statusChange', self)

    def paser_mix_data(self, data):
        mix_command = data.split(':')[0].upper()
        if 'S' == mix_command:
            ##time.sleep(float(data[2:]))
            self.send_queue_cache.appendleft(('SLEEP', float(data[2:])))
            return ''
        elif 'M' == mix_command:
            data = data[2:]
        bytes_data = bytes(data)
        ##print 'paser_mix_data', bytes_data
        return_data = ''
        while True:
            start_index = bytes_data.find('[')
            if start_index == -1: break
            end_index = bytes_data.find(']')
            if end_index == -1: break
            return_data += bytes_data[0:start_index]
            hex_str = bytes_data[start_index + 1:end_index]
            ##print 'hex_str', hex_str
            if len(bytes_data) > (end_index + 1):
                bytes_data = bytes_data[end_index + 1:]
            else:
                bytes_data = ''
            if not hex_str: continue
            hex_str_split = hex_str.split(' ')
            for h in hex_str_split:
                if h.upper() == 'CRC16':
                    return_data += binascii.a2b_hex(crc16_c(return_data))
                    continue
                if len(h) == 1: h = '0' + h
                if (len(h) % 2) != 0:
                    print 'format error'
                    self.signal_msg.emit('statusBarFlashText', u'输入格式错误')
                    return ''
                return_data += binascii.a2b_hex(h)
        return_data += bytes_data
        return return_data

    def send_data(self, data_type, data):
        if self.socekt is None: return
        if self.status != 'Connect': return
        ##if data_type == 'sendPlainData':
        ##    self.socekt.write(data)
        ##else:
        ##    data = self.paser_mix_data(data)
        ##    if data: self.socekt.write(data)
        ##if data:
        ##    if 'E' in self.display_mode:
        ##        self.signal_msg.emit('appendEchoText', (self, data))
        ##    self.send_counts += len(data)
        ##    self.signal_msg.emit('statusChange', self)
        self.send_thread_queue.put((data_type, data))

    def display_clear(self):
        self.setPlainText('')
        self.last_new_line = 2

    def counter_reset(self):
        self.recv_counts = 0
        self.send_counts = 0
        self.signal_msg.emit('statusChange', self)

    def start_log(self):
        log_name = 'log_' + self.ip_str + '_' + self.port_str + '_' \
                   + datetime.datetime.now().strftime('%Y%m%d%H%M%S') + '.log'
        try:
            self.log_handler = open(log_name, 'wb')
            self.signal_msg.emit('newLineText', (self, 'log: ' + log_name))
        except:
            self.log_handler = None

    def set_display_mode(self, display_mode):
        print 'set display_mode', self.display_mode, '->', display_mode
        if ('C' in self.display_mode and 'C' not in display_mode) \
                or ('H' in self.display_mode and 'H' not in display_mode)\
                or ('C' not in self.display_mode and 'C' in display_mode)\
                or ('H' not in self.display_mode and 'H' in display_mode)\
                or ('T' in self.display_mode and 'T' not in display_mode):
            if self.last_new_line < 2:
                self.signal_msg.emit('newLineText', (self, ''))
            if self.last_new_line < 1:
                self.signal_msg.emit('newLineText', (self, ''))
        if 'L' not in display_mode and self.log_handler:
            try: self.log_handler.close()
            except: pass
            self.log_handler = None
        if 'L' in display_mode and not self.log_handler:
            self.start_log()
        self.display_mode = display_mode
        self.signal_msg.emit('statusChange', self)

    def send_thread(self):
        sleep_timestamp = 0
        sleep_timeout = None
        self.send_queue_cache.clear()
        while True:
            try:
                req, req_data = self.send_thread_queue.get(True, sleep_timeout)
                if req == 'EXIT':
                    print 'send_thread EXIT'
                    while not self.send_thread_queue.empty():
                        self.send_thread_queue.get(False)
                    return
                if self.socekt is None: continue
                if self.status != 'Connect': continue
                self.send_queue_cache.append((req, req_data))
            except:
                pass

            if sleep_timeout:
                current_time = time.time()
                delta_time = current_time - sleep_timestamp
                if delta_time < sleep_timeout:
                    sleep_timeout = sleep_timeout - delta_time
                    sleep_timestamp = current_time
                    continue
                else:
                    sleep_timeout = None

            while len(self.send_queue_cache) > 0:
                req, req_data = self.send_queue_cache.popleft()
                if req == 'SLEEP':
                    print 'SLEEP', req_data
                    sleep_timestamp = time.time()
                    sleep_timeout = req_data
                    break
                elif req == 'sendPlainData':
                    try: self.socekt.write(req_data)
                    except: pass
                else:
                    req_data = self.paser_mix_data(req_data)
                    if req_data:
                        try: self.socekt.write(req_data)
                        except: pass
                if req_data:
                    if 'E' in self.display_mode:
                        self.signal_msg.emit('appendEchoText', (self, req_data))
                    self.send_counts += len(req_data)
                    self.signal_msg.emit('statusChange', self)

    def recv_thread(self):
        if self.socekt is None:
            try:
                if self.mode == 'tcp client':
                    self.socekt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socekt.setblocking(False)
                elif self.mode == 'udp client':
                    self.socekt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.socekt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                elif self.mode == 'com':
                    print self.ip_str, self.port_str
                    ip_str_split = self.ip_str.split(':')
                    port_set = ip_str_split[0]
                    UART_set = self.port_str
                    baudrate_set = 115200
                    if len(ip_str_split) > 1:
                        try: baudrate_set = int(ip_str_split[1])
                        except: pass
                    bytesize_set = uart_bytesize_set.get(UART_set[0], serial.EIGHTBITS)
                    stopbits_set = uart_stopbits_set.get(UART_set[1], serial.STOPBITS_ONE)
                    parity_set = uart_parity_set.get(UART_set[2], serial.PARITY_NONE)
                    self.socekt = serial.Serial(
                        port=port_set,
                        baudrate=baudrate_set,
                        bytesize=bytesize_set,
                        parity=parity_set,
                        stopbits=stopbits_set,
                        timeout=0.001,
                        writeTimeout=0.1)
                    print 'connect ok'
                    self.status = 'Connect'
                    self.signal_msg.emit('newLineText', (self, 'connect success.'))
                    self.signal_msg.emit('statusChange', self)
            except:
                self.socekt = None
                self.status = 'Idle'
                self.signal_msg.emit('newLineText', (self, 'creat socket error.'))
                self.signal_msg.emit('statusChange', self)
                print 'creat socket error'
                return

        if self.mode == 'tcp client' or self.mode == 'udp client':
            while self.socekt is not None:
                ret = client_connect(self.socekt, (self.ip_str, int(self.port_str)))
                if ret == 1:
                    print 'connect ok'
                    self.status = 'Connect'
                    self.signal_msg.emit('newLineText', (self, 'connect success.'))
                    self.signal_msg.emit('statusChange', self)
                    break
                elif ret == -1:
                    print 'connect error'
                    self.signal_msg.emit('newLineText', (self, 'connect failure.'))
                    self.signal_msg.emit('statusChange', self)
                    try:
                        if self.mode != 'com':
                            self.socekt.shutdown(socket.SHUT_RDWR)
                            self.socekt.close()
                    except:
                        pass
                    self.socekt = None
                    self.status = 'Idle'
                    return
                elif ret == 0:
                    time.sleep(0.01)
            if self.socekt is not None:
                self.socekt = SocketSerial(self.socekt)

        while self.socekt is not None:
            try:
                data = self.socekt.read(1024)
                if not data: continue
            except:
                if self.socekt is not None:
                    print 'peer disconnect'
                    self.signal_msg.emit('newLineText', (self, 'peer disconnect.'))
                    self.signal_msg.emit('statusChange', self)
                break
            self.signal_msg.emit('appendText', (self, data))
            self.recv_counts += len(data)
            self.signal_msg.emit('statusChange', self)

        if self.socekt is not None:
            self.socekt.close()
        self.socekt = None
        self.status = 'Idle'
        self.signal_msg.emit('statusChange', self)
        ##print 'recv_thread exit'
