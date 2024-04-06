# About消息框

from PyQt6.QtWidgets import QDialog

about_msg = """
## EzAPIGuard

Version 1.0.2

EzAPIGuard is an API call analysis tool, can be used to analyze, record and intercept dangerous API operations of target process or executable.

API hook based on Microsoft Detours.

[MIT LICENSE](https://gitee.com/xiaoketx/EzAPIGuard/blob/main/LICENSE)

[Project Source](https://gitee.com/xiaoketx/EzAPIGuard)
"""

from . import __AboutDialog

class Ui_Dialog(QDialog, __AboutDialog.Ui_Dialog):
    """About消息框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

        self.textBrowser.setMarkdown(about_msg)
