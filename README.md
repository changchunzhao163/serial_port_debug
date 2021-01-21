### pyqt4 + python2.7.18 串行数据调试器

#### 可实现功能

    串口连接
    tcp client连接
    udp client连接
    tcp listen
    udp listen（待实现）
    接收数据显示可以字符串模式，HEX模式，时间标签模式，回显模式，log模式，单独或组合显示
    可以发送字符串或HEX或组合数据
    接收数据显示页多tab显示
    预设指令页多tab显示
    发送数据对话框组合模式下多组数据顺序发送
    发送文件数据（待实现）
    定间隔发送数据（待实现）
    保存接收原始数据到文件（待实现）

#### 预设指令页

    非编辑模式：双击发送当前行的字符串或者指令
    编辑模式：双击选择word
    退出编辑模式或ctrl+s：保存当前预设指令页

#### 预设指令页和发送数据对话框非字符串发送指令说明：
[]内为可以选部分

    F:文件名
    打开新的预设指令页

    T:IP:端口[:接收数据显示模式]
    tcp client连接
    接收数据显示模式为'C', 'H', 'T', 'E', 'L'几个字符的组合
    分别代表：字符串模式，HEX模式，时间标签模式，回显模式，log模式

    U:IP:端口[:接收数据显示模式]
    udp client连接

    C:串口名[:波特率[:串口配置[:接收数据显示模式]]]
    串口配置为3个数字，比如810
    第一个数字：数据位(5-8)
    第二个数字：停止位(1-3)
        1：1个停止位
        2：2个停止位
        3：1.5个停止位
    第三个数字：校验位(0-3)
        0：无校验
        1：奇校验
        2：偶校验
        3：空校验

    M:字符串或HEX或组合数据
    发送字符串或HEX数据，在[]内的数据为HEX数据，比如：1[32 33]4[0D0A]
    如果在[]内有CRC16标识，标识在此处填充所有前面数据的CRC16校验和
    可用来发送MODBUS指令，比如：[010300000001 CRC16]或者[010300000001][CRC16]
    
    S:浮点数
    以秒为单位，空闲时间。可以作为发送数据对话框组合模式下发送多组数据中的延时处理
 
    TL:IP:端口[[:接收数据显示模式]:S]
    tcp listen监听模式
    如果设置S，为单窗口模式，所有接受的socket连接接收发的数据在同一个窗口显示
    如果为单窗口模式，发送的数据会向所有已接受的socket发送
   