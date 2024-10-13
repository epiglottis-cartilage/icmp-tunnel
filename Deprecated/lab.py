import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QWidget

class LogWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # 创建主布局
        main_layout = QVBoxLayout()

        # 创建 QTextEdit 组件
        self.log_text_edit = QTextEdit(self)
        self.log_text_edit.setReadOnly(True)
        main_layout.addWidget(self.log_text_edit, 4)

        # 创建输入框和按钮布局
        input_layout = QHBoxLayout()

        # 创建 QLineEdit 输入框
        self.input_line_edit = QLineEdit(self)
        input_layout.addWidget(self.input_line_edit)

        # 创建 QPushButton 按钮
        send_button = QPushButton("发送", self)
        send_button.clicked.connect(self.send_text)
        input_layout.addWidget(send_button)

        # 将输入框和按钮布局添加到主布局
        main_layout.addLayout(input_layout, 1)

        # 连接输入框的回车键按下事件到发送文本方法
        self.input_line_edit.returnPressed.connect(self.send_text)

        # 设置中心窗口
        central_widget = QWidget(self)
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # 窗口设置
        self.setWindowTitle("日志记录窗口")
        self.resize(600, 400)

    def send_text(self):
        text = self.input_line_edit.text()
        self.log_text_edit.append(text)
        self.input_line_edit.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LogWindow()
    window.show()
    sys.exit(app.exec_())
