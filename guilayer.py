import sys
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget, QHBoxLayout, QFrame, QLabel

class Cust_QApplication(QApplication):

    def __init__(self, argv):
        super().__init__(argv)




class Cust_QMainWindow(QMainWindow):
    """it has two field: the text box, and the button frame. both are cust class
    it first add two field , and then add fields to layout.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gungnir")
        self.setGeometry(100, 100, 800, 500)

        
        self.dialog_box = QTextEdit(self)#?why fill in self
        self.dialog_box.setReadOnly(True)

        self.button_frame = Cust_buttonframe()


        #add field to layout
        self.main_layout = QVBoxLayout()
        self.main_layout.addWidget(self.dialog_box, 4)
        self.main_layout.addWidget(self.button_frame, 1)


        central_widget = QWidget(self)#again, why fill in self?
        # 感觉像是在嵌套，widget才是本体，外面窗口就是个框架
        central_widget.setLayout(self.main_layout)
        self.setCentralWidget(central_widget)


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

    def update_yourip(self, status:str):
        self.upper.setText(self.upper.text + status)

    def update_tgtip(self, status:str):
        self.down.setText(self.down.text + status)
    

app_main = QApplication(sys.argv)

window = Cust_QMainWindow()
window.show()
sys.exit(app_main.exec_())









