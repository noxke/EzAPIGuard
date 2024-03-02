# 进程查看器窗口

from PyQt6.QtWidgets import QDialog, QTreeWidgetItem
from PyQt6.QtCore import Qt

from . import __ProcessView

import psutil

class Ui_Dialog(QDialog, __ProcessView.Ui_Dialog):
    """进程窗口"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

        self.process_list = []
        self.process_filter = ""

    def view_reset(self):
        """重置窗口"""
        self.resize(480, 680)
        self.processTreeWidget.setColumnWidth(0, 300)
        self.processTreeWidget.setColumnWidth(1, 150)
        self.process_filter = ""
        header = self.processTreeWidget.header()
        header.setSortIndicator(0, Qt.SortOrder.AscendingOrder)

    def return_selected_pid(self):
        """返回选中经常的pid"""
        items = self.processTreeWidget.selectedItems()
        if (len(items) == 0):
            self.done(0)
            return
        pid = int(items[0].text(1))
        self.done(pid)

    def search_filter(self):
        """根据搜索框内容过滤"""
        self.process_filter = self.searchLineEdit.text()
        self.set_process_list()

    def get_process_list(self):
        """获取进程列表"""
        self.process_list.clear()
        proc_list = psutil.process_iter()
        for proc in proc_list:
            self.process_list.append((proc.name(), str(proc.pid)))

    def set_process_list(self):
        """设置进程列表"""
        self.processTreeWidget.clear()
        for proc in self.process_list:
            if ((self.process_filter in proc[0]) or (self.process_filter in proc[1])):
                item = QTreeWidgetItem(None, [proc[0], proc[1]])
                self.processTreeWidget.addTopLevelItem(item)
