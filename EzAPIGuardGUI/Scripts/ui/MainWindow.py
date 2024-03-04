# 主窗口
from PyQt6.QtWidgets import QMainWindow, QFileDialog
from PyQt6.QtCore import Qt, QCoreApplication

from . import __MainWindow
from . import ProcessView
from . import APIRequestDialog
from . import AboutDialog

# 导入EzGuardLib
import os
import sys

main_path = os.getcwd()
scripts_path = os.path.join(main_path, "Scripts")
sys.path.append(scripts_path)

from guardlib import *

CONFIG_OVERVIEW = 0
CONFIG_SELECTED = 1

MODE_ALLOW = 0
MODE_REJECT = 1
MODE_REQUEST = 2

class Ui_MainWindow(QMainWindow, __MainWindow.Ui_MainWindow):
    """主窗口"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

        # 绑定File菜单
        self.recordSave.triggered.connect(self.record_save)
        self.recordLoad.triggered.connect(self.record_load)

        # 绑定Process菜单
        self.process_dialog = ProcessView.Ui_Dialog()
        self.processAttach.triggered.connect(self.process_attach)
        self.processRun.triggered.connect(self.process_run)

        # 绑定ViewReset菜单动作
        self.viewReset.triggered.connect(self.view_reset)
        # 绑定About菜单动作
        self.about_dialog = AboutDialog.Ui_Dialog()
        self.actionAbout.triggered.connect(self.action_about)

        # API请求消息框
        self.api_request_dialog = APIRequestDialog.Ui_Dialog()

        # config显示模式 默认overview
        self.config_mode = CONFIG_OVERVIEW

        # 初始化窗口布局
        self.view_reset()

        # socket服务器
        self.server = UdpSocketServer(RequestHandler=self.MsgHandler)
        self.server_addr = self.server.server_addr
        print(self.server_addr)
        # 注入器
        self.injector = Injector()
        self.injector.init_dll(self.server_addr[1])

    def view_reset(self):
        """重置窗口布局"""
        self.resize(1280, 720)
        # 进程管理器宽度
        self.processListTreeWidget.setColumnWidth(0, 130)
        self.processListTreeWidget.setColumnWidth(1, 60)
        self.processListTreeWidget.setColumnWidth(2, 40)
        header = self.processListTreeWidget.header()
        header.setSortIndicator(0, Qt.SortOrder.AscendingOrder)

        # hook记录宽度
        self.recordTreeWidget.setColumnWidth(0, 200)
        self.recordTreeWidget.setColumnWidth(1, 450)
        self.recordTreeWidget.setColumnWidth(2, 60)
        header = self.recordTreeWidget.header()
        header.setSortIndicator(0, Qt.SortOrder.AscendingOrder)

        # config界面默认显示overview
        self.view_overview()

    def action_about(self):
        """about窗口"""
        self.about_dialog.resize(480, 360)
        self.about_dialog.show()

    def api_request(self, msg:str="")->bool:
        """请求api执行情况"""
        self.api_request_dialog.textBrowser.setMarkdown(msg)
        self.api_request_dialog.exec()
        if (self.api_request_dialog.result() == 1):
            return True
        else:
            return False

    def process_attach(self):
        """附加进程"""
        self.process_dialog.view_reset()
        self.process_dialog.get_process_list()
        self.process_dialog.set_process_list()
        self.process_dialog.exec()
        print("attach process:", self.process_dialog.result())

    def process_run(self):
        """启动进程"""
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Run a new process")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setNameFilter("Executable Files (*.exe)");
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            print("Selected file:", selected_file)


    def record_save(self):
        """保存记录"""
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Save records")
        file_dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        file_dialog.setNameFilter("JSON Files (*.json)");
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            print("Selected file:", selected_file)

    def record_load(self):
        """加载记录"""
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Load records")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setNameFilter("JSON Files (*.json)");
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            print("Selected file:", selected_file)

    def select_process(self):
        """选中的进程改变"""
        pass

    def record_search_filter(self):
        """record搜索过滤器"""
        pass

    def view_selected(self):
        """切换config view到选中的进程"""
        self.config_mode = CONFIG_SELECTED
        self.selectedButton.setChecked(True)
        self.overviewButton.setChecked(False)
        self.processNameLabel_.setText(QCoreApplication.translate("MainWindow", "ProcessName:"))
        self.processNameLabel.setText("test.exe")

    def view_overview(self):
        """切换config view到全局"""
        self.config_mode = CONFIG_OVERVIEW
        self.selectedButton.setChecked(False)
        self.overviewButton.setChecked(True)
        self.processNameLabel_.setText(QCoreApplication.translate("MainWindow", "ProcessNum:"))
        self.processNameLabel.setText("11")

    def rules_config(self):
        """规则发生改变"""
        pass

    def hook_enable(self):
        """启用hook进程"""
        pass

    def hook_disable(self):
        """停止hook进程"""
        pass

    def hook_unload(self):
        """卸载hook"""
        pass

    def kill_process(self):
        """杀掉目标进程"""
        pass

    def handle(self):
        """处理UDP消息"""
        data, socket = self.request
        # 处理接收到的 UDP 数据
        print("({} : {}".format(self.client_address, data.decode()))

    class MsgHandler(UdpSocketServer.UDPHandler):
        """UDP消息处理器"""
        def handle(self):
            super.handle()
