# API调用请求消息框

from PyQt6.QtWidgets import QDialog

from . import __APIRequestDialog

class Ui_Dialog(QDialog, __APIRequestDialog.Ui_Dialog):
    """API调用请求消息框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)