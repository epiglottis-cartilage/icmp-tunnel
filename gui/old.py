import sys
from PyQt5.QtCore import pyqtSignal, QDateTime
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit,\
    QVBoxLayout, QWidget, QHBoxLayout, QFrame, QLabel, QLineEdit, QShortcut
from PyQt5.QtGui import QKeySequence
from functools import partial

import util.icmp_util as icmplib


class Cust_QApplication(QApplication):

    def __init__(self, argv):
        '''fields: main_layout: the layout
        log_text_edit: the scrol text area component
        input_line_edit: the input box
        send_button: as it says
        '''
        super().__init__(argv)



class ScrolTextarea(QWidget):
    ''' A scrollable text area with an input box. '''
    def __init__(self, parent):
        super(ScrolTextarea, self).__init__(parent)
        self.main_layout = QVBoxLayout(self)
        # 创建 QTextEdit 组件
        self.log_text_edit = QTextEdit(self)
        self.log_text_edit.setReadOnly(True)
        self.main_layout.addWidget(self.log_text_edit, 4)
        # 创建输入框和按钮布局
        input_layout = QHBoxLayout()
        # 创建 QLineEdit 输入框
        self.input_line_edit = QLineEdit(self)
        input_layout.addWidget(self.input_line_edit)
        # 创建 QPushButton 按钮
        self.send_button = QPushButton("发送", self)
        self.send_button.clicked.connect(self.cust_send_message)  # 按钮点击事件连接到 send_message 方法
        input_layout.addWidget(self.send_button)
        # 将输入框和按钮布局添加到主布局
        self.main_layout.addLayout(input_layout, 1)
        self.input_line_edit.returnPressed.connect(self.cust_send_message)  # 回车键事件连接到 send_message 方法


    

    def send_message(self):
        '''read text from the inputline field, send it and clear inputline
        This method assume that you have already initialize the callback_function field. If not, a error raise
        '''
        message = self.input_line_edit.text()
        if message:
            current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            formatted_message = f"<div style='text-align: right;'><small>You, {current_time}</small><p>{message}</p></div>"
            self.log_text_edit.append(formatted_message)
            self.input_line_edit.clear()
            return message

    def cust_send_message(self):
        #read father field, sync icmp sr1
        message = self.send_message()
        parent = self.parentWidget().parentWidget()#you sick?????????
        tgtip = parent.get_target_ip()
        print(tgtip)
        parent.icmpclient.sr1(load=str(message).encode(),dst=tgtip)
        


    def receive_message(self, message):
        if message:
            current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            formatted_message = f"<div style='text-align: left;'><small>Other, {current_time}</small><p>{message}</p></div>"
            self.log_text_edit.append(formatted_message)
        

        


class Cust_QMainWindow(QMainWindow):
    """it has two field: the text box, and the button frame. both are cust class
    it first add two field , and then add fields to layout.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gungnir")
        self.setGeometry(100, 100, 800, 500)

        
        self.dialog_box = ScrolTextarea(self)
        self.button_frame = Cust_buttonframe()


        #add field to layout
        self.main_layout = QVBoxLayout()
        self.main_layout.addWidget(self.dialog_box, 4)
        self.main_layout.addWidget(self.button_frame, 1)


        central_widget = QWidget(self)#again, why fill in self?
        # 感觉像是在嵌套，widget才message是本体，外面窗口就是个框架
        central_widget.setLayout(self.main_layout)
        self.setCentralWidget(central_widget)
        
        self.bind_newtarget()

        self.new_tgt_shortcut = QShortcut(QKeySequence("n"), self)
        self.new_tgt_shortcut.activated.connect(self.open_ip_inputwindow)

        self.retry_shortcut = QShortcut(QKeySequence("r"), self)
        self.retry_shortcut.activated.connect(self.retry_connect)

        self.bind_reconnect(self.update_diabox)

        def icmp_handler_override(self, packet):
            msg_content = icmplib.IcmpTunnel.default_cmd_handler(packet)
            self.dialog_box.receive_message(msg_content)

        self.icmpclient = icmplib.IcmpTunnel(partial(icmp_handler_override, self))

        self.justatest = "string"
        
    def get_target_ip(self) -> str:
        return self.button_frame.right.get_tgtip()



    def bind_newtarget(self):
        self.button_frame.left.bind_newtgtbutton(self.open_ip_inputwindow)

    def update_diabox(self):
        self.dialog_box.receive_message("test")
    
    def bind_reconnect(self, callback_function):
        self.button_frame.left.bind_retrybutton(callback_function)
    
    def update_userip(self, status:str):
        self.button_frame.right.update_yourip(status) 
        

    
    def open_ip_inputwindow(self):
        self.tmp_ipinput_window = IPInputWindow()
        self.tmp_ipinput_window.input_ip.connect(self.update_tgtip)# signal emit
        self.tmp_ipinput_window.show()

    def update_tgtip(self, ip):
        self.button_frame.right.update_tgtip(ip)

    def retry_connect(self):
        pass
        

class Cust_buttonframe(QFrame):
    '''this class has two field: left and right. Right holds two ip, while left holds connection&button
    
    '''

    def __init__(self):
        super().__init__()
        self.self_layout = QHBoxLayout(self)

        self.right = RightPart()
        self.self_layout.addWidget(self.right)
        
        #这段就是屎，但只要我包装好了就不需要任何人来吃它
        self.left = LeftPart()
        self.self_layout.addWidget(self.left)


        self.self_layout.addWidget(self.left, 7)
        self.self_layout.addWidget(self.right, 3)

        

class LeftPart(QWidget):
    '''downer left component class'''
    def __init__(self):
        super().__init__()
        self.thislayout = QVBoxLayout(self)
        self.upper = QLabel("Connection: ", self)
        self.thislayout.addWidget(self.upper)

        self.down = QWidget(self)
        self.down.sublayout = QHBoxLayout(self.down)
        self.down.left = QPushButton("Retry Connect", self.down)
        self.down.right = QPushButton("New Target", self.down)


        self.down.sublayout.addWidget(self.down.left)
        self.down.sublayout.addWidget(self.down.right)
        self.thislayout.addWidget(self.down)

    def bind_retrybutton(self,callback_function):
        ''''''
        self.down.left.clicked.connect(callback_function)

    def bind_newtgtbutton(self, callback_function):
        self.down.right.clicked.connect(callback_function)

    def updatestatus(self, status:str):
        self.upper.setText("Connection: "+status)
    

class RightPart(QWidget):
    def __init__(self):
        super().__init__()
        self.rightlayout = QVBoxLayout(self)
        self.upper = QLabel("Your IP:", self)
        self.down = QLabel("Target IP:", self)
        self.rightlayout.addWidget(self.upper)
        self.rightlayout.addWidget(self.down)

    def get_yourip(self):
        return self.upper.text().split(":")[-1]

    def get_tgtip(self):
        return self.down.text().split(":")[-1]

    def update_yourip(self, status:str):
        self.upper.setText("Your IP:" + status)

    def update_tgtip(self, status:str):
        self.down.setText("Target IP:" + status)
    

#这段也是屎
class IPInputWindow(QWidget):
    input_ip = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle('Input Target IP')

        self.label = QLabel('Input Target IP:', self)

        self.entry = QLineEdit(self)
        self.entry.returnPressed.connect(self.confirm)

        self.cancel_button = QPushButton('cancel', self)
        self.cancel_button.clicked.connect(self.cancel)

        self.confirm_button = QPushButton('confirm', self)
        self.confirm_button.clicked.connect(self.confirm)

        hbox = QHBoxLayout()
        hbox.addWidget(self.cancel_button)
        hbox.addWidget(self.confirm_button)

        vbox = QVBoxLayout()
        vbox.addWidget(self.label)
        vbox.addWidget(self.entry)
        vbox.addLayout(hbox)

        self.setLayout(vbox)
        self.entry.setFocus()

        self.confirm_shortcut = QShortcut(QKeySequence("Return"), self)
        self.confirm_shortcut.activated.connect(self.confirm)

        self.cancel_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.cancel_shortcut.activated.connect(self.cancel)

    def confirm(self):
        ip = self.entry.text()
        self.input_ip.emit(ip)
        self.close()

    def cancel(self):
        self.close()


    
    
    
    
    
    


