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

        self.__process_list = []
        self.__process_filter = ""

    def exec(self):
        self.__view_reset()
        self.__get_process_list()
        self.__set_process_list()
        super().exec()

    def __view_reset(self):
        """重置窗口"""
        self.resize(480, 680)
        self.processTreeWidget.setColumnWidth(0, 300)
        self.processTreeWidget.setColumnWidth(1, 150)
        self.process_filter = ""
        self.searchLineEdit.clear()
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
        self.__set_process_list()

    def __get_process_list(self):
        """获取进程列表"""
        self.__process_list.clear()
        self.processTreeWidget.clear()
        proc_list = psutil.process_iter()
        for proc in proc_list:
            item = QTreeWidgetItem(None, [proc.name(), str(proc.pid)])
            item.setHidden(False)
            self.processTreeWidget.addTopLevelItem(item)
            self.__process_list.append((proc.name(), str(proc.pid), item))

    def __set_process_list(self):
        """设置进程列表"""
        for proc in self.__process_list:
            if ((self.process_filter in proc[0]) or (self.process_filter in proc[1])):
                proc[2].setHidden(False)
            else:
                proc[2].setHidden(True)
