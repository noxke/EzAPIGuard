# 主窗口
from PyQt6.QtWidgets import QMainWindow, QFileDialog, QTreeWidgetItem, QComboBox, QLabel
from PyQt6.QtCore import Qt, QCoreApplication

from . import __MainWindow
from . import ProcessView
from . import APIRequestDialog
from . import AboutDialog

import os
import sys
import time
import psutil
import struct
from threading import Thread

main_path = os.getcwd()
scripts_path = os.path.join(main_path, "Scripts")
sys.path.append(scripts_path)
# 导入EzGuardLib
from guardlib import *

# 控制页面选择
CONFIG_OVERVIEW = 0
CONFIG_SELECTED = 1

RULE_NUMS = 7
# 进程状态
STATUS_UNHOOK = "Unhook"
STATUS_HOOKED = "Hooked"
STATUS_DISCONNECT = "Disconnect"
STATUS_DISABLE = "Disabled"
STATUS_EXIT = "Exited"

# hook规则
RULE_ALLOW = 0
RULE_REJECT = 1
RULE_REQUEST = 2
RULE_UNHOOK = 3


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
        self.__config_mode = CONFIG_OVERVIEW

        # socket服务器
        self.server = UdpSocketServer(RequestHandler=self.udp_handler)
        self.server_addr = self.server.server_addr
        self.server.start_handler_thread()

        # 注入器
        self.injector = Injector()
        self.injector.init_dll(self.server_addr[1])
        # 分析器
        self.analyzer = ApiAnalyzer()

        # 进程列表
        self.__proc_list = []
        self.__selected_proc: self.Proc = None

        # 全局配置
        self.__overview_rules = [RULE_ALLOW for _ in range(RULE_NUMS)]
        self.__overview_cnts = [0 for _ in range(RULE_NUMS)]
        self.__rule_items = [
            self.heapRule,
            self.heapRiskRule,
            self.fileRule,
            self.fileRiskRule,
            self.registryRule,
            self.registryRiskRule,
            self.networkRiskRule
        ]
        self.__cnt_items = [
            self.heapCnt,
            self.heapRiskCnt,
            self.fileCnt,
            self.fileRiskCnt,
            self.registryCnt,
            self.registryRiskCnt,
            self.networkRiskCnt
        ]

        # 界面变化状态 避免切换时鬼畜
        self.__view_switching = False

        # 页面刷新线程
        self.__keep_flash = True
        self.flash_thread = Thread(target=self.flash_thread_func)
        self.flash_thread.start()

        # 初始化窗口布局
        self.view_reset()

    def closeEvent(self, event):
        """窗口关闭时结束所有线程"""
        self.__keep_flash = False
        self.flash_thread.join()
        self.server.stop_handler_thread()
        event.accept()

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
        self.searchLineEdit.clear()

        # config界面默认显示overview
        self.view_overview()

    def record_save(self):
        """保存记录"""
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Save records")
        file_dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        file_dialog.setNameFilter("JSON Files (*.json)")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            print("Selected file:", selected_file)

    def record_load(self):
        """加载记录"""
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Load records")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setNameFilter("JSON Files (*.json)")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            print("Selected file:", selected_file)

    def action_about(self):
        """about窗口"""
        self.about_dialog.resize(480, 360)
        self.about_dialog.show()

    def api_request(self, msg: str = "") -> bool:
        """请求api执行情况"""
        self.api_request_dialog.textBrowser.setMarkdown(msg)
        self.api_request_dialog.exec()
        if (self.api_request_dialog.result() == 1):
            return True
        else:
            return False

    def record_search_filter(self):
        """record搜索过滤器"""
        pass

    class Proc():
        """进程对象 保持进程信息"""
        def __init__(self, name: str, pid: int):
            self.name = name
            self.pid = pid
            self.records = {}
            self.record_info = []
            self.status = STATUS_DISCONNECT
            # hook规则
            self.rules = [RULE_ALLOW for _ in range(RULE_NUMS)]
            # 默认使用全局设置
            self.rules_overview = [True for _ in range(RULE_NUMS)]
            self.cnt = [0 for _ in range(RULE_NUMS)]
            self.list_item: QTreeWidgetItem = None
            self.ps:psutil.Process = None
            # socket地址
            self.addr = None
            # 上一次回复时间
            self.last_time = 0

    def process_attach(self):
        """附加进程"""
        self.process_dialog.view_reset()
        self.process_dialog.get_process_list()
        self.process_dialog.set_process_list()
        self.process_dialog.exec()
        pid = self.process_dialog.result()
        if (pid != 0):
            # 将进程添加到进程列表
            ps = psutil.Process(pid)
            proc = self.Proc(ps.name(), pid)
            if (not self.injector.inject_pid(pid)):
                print(f"{ps.name()} PID: {pid} Inject failed!")
                return
            proc.status = STATUS_DISCONNECT
            proc.list_item = QTreeWidgetItem(
                None, [proc.name, str(proc.pid), proc.status])
            proc.ps = ps
            self.__proc_list.append(proc)
            self.processListTreeWidget.addTopLevelItem(proc.list_item)
            self.processListTreeWidget.setCurrentItem(proc.list_item)
            self.flash_thread_func(ones=True)

    def process_run(self):
        """启动进程"""
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Run a new process")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setNameFilter("Executable Files (*.exe)")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            pid = self.injector.run_exe(selected_file)
            if (pid == 0):
                print(f"{selected_file} Run and Inject failed!")
                return
            ps = psutil.Process(pid)
            proc = self.Proc(ps.name(), pid)
            proc.status = STATUS_DISCONNECT
            proc.list_item = QTreeWidgetItem(
                None, [proc.name, str(proc.pid), proc.status])
            proc.ps = ps
            self.__proc_list.append(proc)
            self.processListTreeWidget.addTopLevelItem(proc.list_item)
            self.processListTreeWidget.setCurrentItem(proc.list_item)
            self.flash_thread_func(ones=True)

    def select_process(self):
        """选中的进程改变"""
        items = self.processListTreeWidget.selectedItems()
        if (len(items) == 0):
            return
        for proc in self.__proc_list:
            if (items[0] == proc.list_item):
                self.__selected_proc = proc
                break
        self.view_selected()

    def view_selected(self):
        """切换config view到选中的进程"""
        self.__view_switching = True
        self.__config_mode = CONFIG_SELECTED
        time.sleep(0.01)
        self.selectedButton.setChecked(True)
        self.overviewButton.setChecked(False)
        self.processNameLabel_.setText(
            QCoreApplication.translate("MainWindow", "ProcessName:"))
        name = ""
        rules = [RULE_UNHOOK for _ in range(RULE_NUMS)]
        cnts = [0 for _ in range(RULE_NUMS)]
        selected_proc: self.Proc = self.__selected_proc
        if (selected_proc != None):
            name = selected_proc.name
            for i in range(RULE_NUMS):
                rules[i] = selected_proc.rules[i]
                cnts[i] = selected_proc.cnt[i]
        for i in range(RULE_NUMS):
            config_item:QComboBox = self.__rule_items[i]
            cnt_item:QLabel = self.__cnt_items[i]
            config_item.setCurrentIndex(rules[i])
            cnt_item.setText(str(cnts[i]))
        self.processNameLabel.setText(name)
        self.__view_switching = False

    def view_overview(self):
        """切换config view到全局"""
        self.__view_switching = True
        self.__config_mode = CONFIG_OVERVIEW
        time.sleep(0.01)
        self.processListTreeWidget.clearSelection()
        self.selectedButton.setChecked(False)
        self.overviewButton.setChecked(True)
        self.processNameLabel_.setText(
            QCoreApplication.translate("MainWindow", "ProcessNum:"))
        for i in range(RULE_NUMS):
            rule_item:QComboBox = self.__rule_items[i]
            cnt_item:QLabel = self.__cnt_items[i]
            rule_item.setCurrentIndex(self.__overview_rules[i])
            cnt_item.setText(str(self.__overview_cnts[i]))
        self.processNameLabel.setText(str(len(self.__proc_list)))
        self.__view_switching = False

    def flash_thread_func(self, ones: bool = False):
        """界面刷新线程 刷新进程列表中进程的存活状态"""
        while (self.__keep_flash):
            cur_time = time.time()
            for proc in self.__proc_list:
                if (proc.status == STATUS_EXIT):
                    continue
                # 检查连接是否正常
                if (cur_time - proc.last_time > 3):
                    self.__send_hello(proc)
                # 5s无反应 连接断开
                if (cur_time - proc.last_time > 5):
                    proc.status = STATUS_DISCONNECT
                # 检测进程是否存在
                ps: psutil.Process = proc.ps
                if (ps.is_running() == False):
                    proc.status = STATUS_EXIT
                # 刷新status
                item: QTreeWidgetItem = proc.list_item
                item.setData(2, 0, proc.status)
            if (self.__config_mode == CONFIG_SELECTED):
                self.view_selected()
            elif (self.__config_mode == CONFIG_OVERVIEW):
                self.view_overview()
            if (ones == True):
                break
            time.sleep(1)

    def rules_config(self):
        """规则发生改变"""
        # 界面切换时屏蔽规则变化
        if (self.__view_switching == True):
            return
        if (self.__config_mode == CONFIG_OVERVIEW):
            for i in range(RULE_NUMS):
                rule = self.__rule_items[i].currentIndex()
                self.__overview_rules[i] = rule
                for proc in self.__proc_list:
                    if (proc.status != STATUS_HOOKED):
                        continue
                    if (proc.rules_overview[i] == False):
                        continue
                    if (proc.rules[i] != rule):
                        proc.rules[i] = rule
                        # 通信修改hook规则
                        print(f"{proc.name} Rule {i} changed: {rule}")
        elif (self.__config_mode == CONFIG_SELECTED):
            proc = self.__selected_proc
            if (proc == None):
                return
            for i in range(RULE_NUMS):
                rule = self.__rule_items[i].currentIndex()
                if (proc.rules[i] != rule):
                    proc.rules_overview[i] = False
                    proc.rules[i] = rule
                    # 通信修改hook规则
                    print(f"{proc.name} Rule {i} changed: {rule}")


    def hook_enable(self):
        """启用hook进程"""
        proc = self.__selected_proc
        if (proc == None):
            return
        if (proc.addr == None):
            return
        udp_msg = struct.pack(
            APIHook.udp_msg_struct,
            APIHook.MSG_ENABLE,
            struct.calcsize(APIHook.udp_msg_struct),
            0,
            int(time.time())
            )
        self.server.send_to(proc.addr, udp_msg)

    def hook_disable(self):
        """停止hook进程"""
        proc = self.__selected_proc
        if (proc == None):
            return
        if (proc.addr == None):
            return
        udp_msg = struct.pack(
            APIHook.udp_msg_struct,
            APIHook.MSG_DISABLE,
            struct.calcsize(APIHook.udp_msg_struct),
            0,
            int(time.time())
            )
        self.server.send_to(proc.addr, udp_msg)

    def hook_unload(self):
        """卸载hook"""
        proc = self.__selected_proc
        if (proc == None):
            return
        if (proc.addr == None):
            return
        udp_msg = struct.pack(
            APIHook.udp_msg_struct,
            APIHook.MSG_UNLOAD,
            struct.calcsize(APIHook.udp_msg_struct),
            0,
            int(time.time())
            )
        self.server.send_to(proc.addr, udp_msg)

    def kill_process(self):
        """杀掉目标进程 发送kill消息"""
        proc = self.__selected_proc
        if (proc == None):
            return
        ps = proc.ps
        ps.kill()

    def __send_hello(self, proc:Proc):
        """向进程发送hello 检测进程存活状态"""
        if (proc.addr == None):
            return
        udp_msg = struct.pack(
            APIHook.udp_msg_struct,
            APIHook.MSG_HELLO,
            struct.calcsize(APIHook.udp_msg_struct),
            0,
            int(time.time())
            )
        self.server.send_to(proc.addr, udp_msg)

    def __send_ack(self, proc:Proc):
        """向进程发送ack 回复hello"""
        if (proc.addr == None):
            return
        udp_msg = struct.pack(
            APIHook.udp_msg_struct,
            APIHook.MSG_ACK,
            struct.calcsize(APIHook.udp_msg_struct),
            0,
            int(time.time())
            )
        self.server.send_to(proc.addr, udp_msg)

    def udp_handler(self, request, client_address, server):
        """udp消息处理器"""
        data, socket = request
        if (len(data) < 16):
            return
        # 处理接收到的 UDP 数据
        udp_msg = struct.unpack(APIHook.udp_msg_struct, data[:16])
        msg_type = udp_msg[0]
        msg_len = udp_msg[1]
        if (msg_len != len(data)):
            return
        msg_pid = udp_msg[2]
        msg_time = udp_msg[3]
        proc = None
        for p in self.__proc_list:
            if (p.pid == msg_pid):
                proc = p
                break
        if (proc == None):
            return
        proc.last_time = msg_time
        if (proc.addr == None):
            proc.addr = client_address
        match msg_type:
            case APIHook.MSG_HELLO:
                print(f"hello from {client_address}")
                proc.status = STATUS_HOOKED
                self.__send_ack(proc)
            case APIHook.MSG_ACK:
                print(f"ack from {client_address}")
                pass
            case APIHook.MSG_CONFIG:
                pass
            case APIHook.MSG_ENABLE:
                proc.status = STATUS_HOOKED
            case APIHook.MSG_DISABLE:
                proc.status = STATUS_UNHOOK
            case APIHook.MSG_UNLOAD:
                proc.status = STATUS_DISCONNECT
            case APIHook.MSG_HOOKED:
                api_msg = struct.unpack(APIHook.api_hooked_msg_struct, data[:20])
                api_id = api_msg[4]
                api_arg_num = api_msg[5]
                print(f"API {api_id} hooked!")
            case _:
                pass