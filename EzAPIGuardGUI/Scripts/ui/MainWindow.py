# 主窗口
from PyQt6.QtWidgets import QMainWindow, QFileDialog, QTreeWidgetItem, QComboBox, QLabel
from PyQt6.QtCore import Qt, QCoreApplication, QThread, pyqtSignal

from . import __MainWindow
from . import ProcessView
from . import APIRequestDialog
from . import AboutDialog

import os
import sys
import time
import psutil
import struct
import ast
from threading import Thread

main_path = os.getcwd()
scripts_path = os.path.join(main_path, "Scripts")
sys.path.append(scripts_path)
# 导入EzGuardLib
from guardlib import *

# 控制页面选择
CONFIG_OVERVIEW = 0
CONFIG_SELECTED = 1

RULE_NUMS = 4
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
        self.server = UdpSocketServer()
        self.server_addr = self.server.server_addr
        # udp消息接收线程
        self.udp_thread = self.UDPThread(self.server)
        self.udp_thread.signal.connect(self.__udp_handler)
        self.udp_thread.start()

        # 注入器
        self.injector = Injector()
        self.injector.init_dll(self.server_addr[1])
        # 分析器
        self.analyzer = ApiAnalyzer()

        # 进程列表
        self.__proc_list = []
        self.__selected_proc: self.Proc = None

        # 记录列表以及flitter
        self.__record_list = [] # [{proc, "args_str", treeListItem}]
        self.__record_filter = ""

        # 全局配置
        self.__overview_rules = [
            None,
            {"rule":RULE_ALLOW, "item":self.fileRule, "cnt":self.fileCnt},
            {"rule":RULE_ALLOW, "item":self.heapRule, "cnt":self.heapCnt},
            {"rule":RULE_ALLOW, "item":self.registryRule, "cnt":self.registryCnt},
            {"rule":RULE_ALLOW, "item":self.networkRule, "cnt":self.networkCnt}
        ]

        # 界面变化状态 避免切换时鬼畜
        self.__view_switching = False

        # 页面刷新线程
        self.__keep_running = True
        self.flash_thread = QThread(self)
        self.flash_thread.run = lambda:self.__flash_thread()
        self.flash_thread.start()

        # 初始化窗口布局
        self.view_reset()

    def closeEvent(self, event):
        """窗口关闭时结束所有线程"""
        self.__keep_running = False
        self.udp_thread.stop()
        self.udp_thread.wait()
        self.flash_thread.wait()
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
        if file_dialog.exec() != QFileDialog.DialogCode.Accepted:
            return
        selected_file = file_dialog.selectedFiles()[0]
        f = open(selected_file, "wt")
        for p in self.__proc_list:
            proc_dict = p.__dict__
            if (proc_dict["pid"] > 0):
                proc_dict["pid"] = - proc_dict["pid"]   # 改为复数避免冲突
            proc_dict.pop("list_item")
            proc_dict.pop("ps")
            proc_dict.pop("addr")
            proc_dict.pop("status")
            f.write(str(proc_dict)+'\n')
        f.close()


    def record_load(self):
        """加载记录"""
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Load records")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setNameFilter("JSON Files (*.json)")
        if file_dialog.exec() != QFileDialog.DialogCode.Accepted:
            return
        selected_file = file_dialog.selectedFiles()[0]
        f =  open(selected_file, "rt")
        for line in f.readlines():
            try:
                d = ast.literal_eval(line)
                # 添加进程记录
                p = self.Proc(d["name"], d["pid"])
                p.records = d["records"]
                p.record_info = d["record_info"]
                p.status = STATUS_EXIT
                p.rules = d["rules"]
                p.list_item = QTreeWidgetItem(
                None, [p.name, str(-p.pid), p.status])
                self.__proc_list.append(p)
                self.processListTreeWidget.addTopLevelItem(p.list_item)
                # 添加api记录
                for api in d["records"]:
                    api_args = api["api_args"]
                    api_name = api["name"]
                    api_time = api["time"]
                    api_rule = api["rule"]
                    item = QTreeWidgetItem(None, 
                    [api_name, f"[{p.name}]  {time.ctime(api_time)}", api_rule])
                    # 添加参数到记录item中
                    for key, value in api_args.items():
                        QTreeWidgetItem(item, [key, str(value)])
                    self.__record_list.append({"proc":p, "args_str":f"{api_name}{api_args}", "treeListItem":item})
                    if (p != self.__selected_proc and self.__config_mode != CONFIG_OVERVIEW):
                        item.setHidden(True)
                    self.recordTreeWidget.addTopLevelItem(item)
            except:
                continue
        f.close()

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
        self.__record_filter = self.searchLineEdit.text()
        self.__flash_record()
    
    def __flash_record(self):
        """刷新日志"""
        for record in self.__record_list:
            if (record["proc"] == self.__selected_proc or self.__config_mode == CONFIG_OVERVIEW):
                if (self.__record_filter in record["args_str"]):
                    record["treeListItem"].setHidden(False)
                else:
                    record["treeListItem"].setHidden(True)
            else:
                record["treeListItem"].setHidden(True)

    def __flash_thread(self):
        """界面刷新线程 刷新进程列表中进程的存活状态"""
        while (self.__keep_running):
            time.sleep(0.2)
            cur_time = time.time()
            for proc in self.__proc_list:
                if (proc.pid < 0):  # 新创建进程或导入的记录
                    continue
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
                if (ps == None):
                    continue
                if (ps.is_running() == False):
                    proc.status = STATUS_EXIT
                # 刷新status
                item: QTreeWidgetItem = proc.list_item
                item.setData(2, 0, proc.status)
            # 刷新cnt
            cnts = [0, 0, 0, 0, 0]
            warn_cnt = 0
            proc_name = ""
            if (self.__config_mode == CONFIG_SELECTED):
                selected_proc = self.__selected_proc
                if (selected_proc == None):
                    continue
                warn_cnt = selected_proc.warn_cnt
                for i in range(len(selected_proc.rules)):
                    cnts[i] = selected_proc.rules[i]["cnt"]
                proc_name = selected_proc.name
            else:
                for p in self.__proc_list:
                    warn_cnt += p.warn_cnt
                    for i in range(len(p.rules)):
                        cnts[i] += p.rules[i]["cnt"]
                proc_name = str(len(self.__proc_list))
            for key in range(1, len(self.__overview_rules)):
                value = self.__overview_rules[key]
                rule_item:QComboBox = value["item"]
                cnt_item:QLabel = value["cnt"]
                cnt_item.setText(str(cnts[key]))
            self.processNameLabel.setText(proc_name)
            self.hookedCnt.setText(str(sum(cnts))+" Hooked")
            self.warningCnt.setText(str(warn_cnt)+" Warning")

    class Proc():
        """进程对象 保持进程信息"""
        def __init__(self, name: str, pid: int):
            self.name = name
            self.pid = pid
            self.records = []
            self.record_info = []
            self.status = STATUS_DISCONNECT
            # hook规则
            self.rules = [
                {"rule":RULE_ALLOW, "overview":True, "cnt":0},
                {"rule":RULE_ALLOW, "overview":True, "cnt":0},
                {"rule":RULE_ALLOW, "overview":True, "cnt":0},
                {"rule":RULE_ALLOW, "overview":True, "cnt":0},
                {"rule":RULE_ALLOW, "overview":True, "cnt":0}
            ]
            # warning cnt
            self.warn_cnt = 0
            self.list_item: QTreeWidgetItem = None
            self.ps:psutil.Process = None
            # socket地址
            self.addr = None
            # 上一次回复时间
            self.last_time = 0

    def process_attach(self):
        """附加进程"""
        self.process_dialog.exec()
        pid = self.process_dialog.result()
        if (pid != 0):
            ps = psutil.Process(pid)
            proc = None
            # 检查进程在不在列表里面
            for p in self.__proc_list:
                if (p.pid == pid and p.name == ps.name()):
                    proc = p
                    break
            if (proc != None):
                # 进程已经在列表中 再注入一次
                self.injector.inject_pid(pid)
                return
            proc = self.Proc(ps.name(), pid)
            # 将进程添加到进程列表
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

    def process_run(self):
        """启动进程"""
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Run a new process")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setNameFilter("Executable Files (*.exe)")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_file = file_dialog.selectedFiles()[0]
            # 创建线程避免主线程阻塞
            thread = Thread(target=self.__process_run, kwargs={"exe_file":selected_file})
            thread.start()


    def __process_run(self, exe_file):
        # 启动前先将进程添加到进程列表中 使能先接收到进程的数据包
        proc = self.Proc(os.path.basename(exe_file), -1)
        proc.status = STATUS_DISCONNECT
        self.__proc_list.append(proc)
        pid = self.injector.run_exe(exe_file)
        if (pid == 0):
            print(f"{exe_file} Run and Inject failed!")
            self.__proc_list.remove(proc)
            return
        ps = psutil.Process(pid)
        proc.pid = ps.pid
        proc.ps = ps
        proc.list_item = QTreeWidgetItem(
            None, [proc.name, str(proc.pid), proc.status])
        self.processListTreeWidget.addTopLevelItem(proc.list_item)
        self.processListTreeWidget.setCurrentItem(proc.list_item)

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
        selected_proc: self.Proc = self.__selected_proc
        cnts = [0, 0, 0, 0, 0]
        rules = [RULE_ALLOW for _ in range(5)]
        warn_cnt = 0
        proc_name = ""
        if (selected_proc != None):
            warn_cnt = selected_proc.warn_cnt
            proc_name = selected_proc.name
            for i in range(len(selected_proc.rules)):
                cnts[i] = selected_proc.rules[i]["cnt"]
                rules[i] = selected_proc.rules[i]["rule"]
            for key in range(1, len(self.__overview_rules)):
                value = self.__overview_rules[key]
                rule_item:QComboBox = value["item"]
                cnt_item:QLabel = value["cnt"]
                rule_item.setCurrentIndex(rules[key])
                cnt_item.setText(str(cnts[key]))
        self.processNameLabel.setText(proc_name)
        self.hookedCnt.setText(str(sum(cnts))+" Hooked")
        self.warningCnt.setText(str(warn_cnt)+" Warning")

        self.__flash_record()
        self.__view_switching = False

    def view_overview(self):
        """切换config view到全局"""
        self.__view_switching = True
        self.__config_mode = CONFIG_OVERVIEW
        # self.__selected_proc = None
        time.sleep(0.01)

        # self.processListTreeWidget.clearSelection()
        self.selectedButton.setChecked(False)
        self.overviewButton.setChecked(True)
        self.processNameLabel_.setText(
            QCoreApplication.translate("MainWindow", "ProcessNum:"))
        cnts = [0, 0, 0, 0, 0]
        warn_cnt = 0
        for p in self.__proc_list:
            warn_cnt += p.warn_cnt
            for i in range(len(p.rules)):
                cnts[i] += p.rules[i]["cnt"]
        for key in range(1, len(self.__overview_rules)):
            value = self.__overview_rules[key]
            rule_item:QComboBox = value["item"]
            cnt_item:QLabel = value["cnt"]
            rule_item.setCurrentIndex(value["rule"])
            cnt_item.setText(str(cnts[key]))
        self.processNameLabel.setText(str(len(self.__proc_list)))
        self.hookedCnt.setText(str(sum(cnts))+" Hooked")
        self.warningCnt.setText(str(warn_cnt)+" Warning")

        self.__flash_record()
        self.__view_switching = False

    def rules_config(self):
        """规则发生改变"""
        # 界面切换时屏蔽规则变化
        if (self.__view_switching == True):
            return
        if (self.__config_mode == CONFIG_OVERVIEW):
            for i in range(1, len(self.__overview_rules)):
                value = self.__overview_rules[i]
                rule = value["item"].currentIndex()
                self.__overview_rules[i]["rule"] = rule
                # 修改每个进程的规则
                for proc in self.__proc_list:
                    if (proc.status != STATUS_HOOKED):
                        continue
                    if (proc.rules[i]["overview"] == False):
                        # 不随全局规则变化
                        continue
                    if (proc.rules[i]["rule"] != rule):
                        proc.rules[i]["rule"] = rule
                        # 通信修改hook规则
                        self.__rule_config(proc)
        elif (self.__config_mode == CONFIG_SELECTED):
            proc = self.__selected_proc
            if (proc == None):
                return
            if (proc.status != STATUS_HOOKED):
                return
            for i in range(1, len(self.__overview_rules)):
                value = self.__overview_rules[i]
                rule = value["item"].currentIndex()
                if (proc.rules[i]["rule"] != rule):
                    proc.rules[i]["overview"] = False
                    proc.rules[i]["rule"] = rule
                    # 通信修改hook规则
                    self.__rule_config(proc)

    def __rule_config(self, proc:Proc):
        """配置api hook规则"""
        if (proc == None):
            return
        if (proc.status == STATUS_EXIT or proc.status == STATUS_DISCONNECT or proc.addr == None):
            return
        file_rule = proc.rules[APIHook.API_TYPE_FILE]["rule"]
        heap_rule = proc.rules[APIHook.API_TYPE_HEAP]["rule"]
        registry_rule = proc.rules[APIHook.API_TYPE_REG]["rule"]
        network_rule = proc.rules[APIHook.API_TYPE_NET]["rule"]
        udp_msg = struct.pack(
            APIHook.udp_msg_struct,
            APIHook.MSG_CONFIG,
            struct.calcsize(APIHook.udp_msg_struct) + 0x50,
            0,
            int(time.time())
        )
        udp_msg += struct.pack("B", RULE_ALLOW) * 0x10
        udp_msg += struct.pack("B", file_rule) * 0x10
        udp_msg += struct.pack("B", heap_rule) * 0x10
        udp_msg += struct.pack("B", registry_rule) * 0x10
        udp_msg += struct.pack("B", network_rule) * 0x10
        self.server.send_to(proc.addr, udp_msg)

    def hook_enable(self):
        """启用hook进程"""
        proc = self.__selected_proc
        if (proc == None):
            return
        if (proc.status == STATUS_EXIT or proc.status == STATUS_DISCONNECT or proc.addr == None):
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
        if (proc.status == STATUS_EXIT or proc.status == STATUS_DISCONNECT or proc.addr == None):
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
        if (proc.status == STATUS_EXIT or proc.status == STATUS_DISCONNECT or proc.addr == None):
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
        try:
            proc = self.__selected_proc
            ps = proc.ps
            ps.kill()
        except:
            print("kill process selected failed")

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

    def __api_reply(self, reply:False, addr):
        """回复api请求"""
        udp_msg = struct.pack(
            APIHook.api_reply_msg_struct,
            APIHook.MSG_REPLY,
            struct.calcsize(APIHook.api_reply_msg_struct),
            0,
            int(time.time()),
            reply
            )
        self.server.send_to(addr, udp_msg)

    class UDPThread(QThread):
        """UDP子线程"""
        signal = pyqtSignal(bytes, tuple)
        def __init__(self, server):
            super().__init__()
            self.server = server
            self.__keep_runing = True

        def run(self):
            while (self.__keep_runing):
                data, client_address = self.server.get_request()
                if (data != None and client_address != None):
                    self.signal.emit(data, client_address)
        
        def stop(self):
            self.__keep_runing = False

    def __udp_handler(self, data, client_address):
        """udp消息处理器"""
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
        # 进程已退出则不能使用psutil打开进程
        try:
            msg_proc_name = psutil.Process(msg_pid).name()
            for p in self.__proc_list:
                if ((p.name == msg_proc_name) and ((p.pid == msg_pid) or (p.pid == -1))):
                    proc = p
                    break
        except:
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
                proc.status = STATUS_HOOKED
                self.__send_ack(proc)
            case APIHook.MSG_ACK:
                if (proc.status == STATUS_DISCONNECT):
                    proc.status = STATUS_HOOKED
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
                self.__api_hooked(proc, data, client_address)
            case APIHook.MSG_KILL:
                proc.status = STATUS_EXIT
            case _:
                pass

    def __api_hooked(self, proc:Proc, api_msg_data, addr):
        """api hook记录 处理api请求"""
        check_info = self.analyzer.checker(api_msg_data)

        #! temp log
        print(check_info)

        api_msg = struct.unpack(APIHook.api_hooked_msg_struct, api_msg_data[:24])
        api_time = api_msg[3]
        api_id = api_msg[4]
        api_name_off = api_msg[6]
        api_name_len = api_msg[7]
        # name+4是为了去除宏里面带的API_
        api_name = api_msg_data[api_name_off+4:api_name_off+api_name_len].decode(encoding="ansi")
        api_arg_num = api_msg[5]
        api_args = {}
        # print(api_name)
        for i in range(api_arg_num):
            (arg_name_off, arg_name_len, arg_off, arg_len) = \
                struct.unpack("H H H H", api_msg_data[24+i*8:32+i*8])
            arg_name = api_msg_data[arg_name_off:arg_name_off+arg_name_len].decode(encoding="ansi")
            arg_value = api_msg_data[arg_off:arg_off+arg_len]
            api_args[arg_name] = arg_value
            # print(arg_name, arg_value)

        api_type = api_id >> 4
        api_rule = proc.rules[api_type]["rule"]
        # 计数器
        proc.rules[api_type]["cnt"] += 1

        match api_id:
            case APIHook.API_MessageBoxA | APIHook.API_MessageBoxW:
                for key in api_args.keys():
                    api_args[key] = api_args[key].decode(encoding="ansi")

            case APIHook.API_CreateFile:
                api_args["lpFileName"] = api_args["lpFileName"].decode(encoding="ansi")
                api_args["dwDesiredAccess"] = hex(int.from_bytes(api_args["dwDesiredAccess"], 'little'))
                api_args["dwShareMode"] = hex(int.from_bytes(api_args["dwShareMode"], 'little'))
                api_args["dwCreationDisposition"] = hex(int.from_bytes(api_args["dwCreationDisposition"], 'little'))
                api_args["dwFlagsAndAttributes"] = hex(int.from_bytes(api_args["dwFlagsAndAttributes"], 'little'))
            case APIHook.API_ReadFile:
                api_args["hFile"] = api_args["hFile"].decode(encoding="ansi")
                api_args["nNumberOfBytesToRead"] = int.from_bytes(api_args["nNumberOfBytesToRead"], 'little')
            case APIHook.API_WriteFile:
                api_args["hFile"] = api_args["hFile"].decode(encoding="ansi")
                api_args["nNumberOfBytesToWrite"] = int.from_bytes(api_args["nNumberOfBytesToWrite"], 'little')
            case APIHook.API_DeleteFile:
                api_args["lpFileName"] = api_args["lpFileName"].decode(encoding="ansi")

            case APIHook.API_HeapCreate | APIHook.API_HeapDestroy\
                | APIHook.API_HeapAlloc | APIHook.API_HeapFree:
                for key, value in api_args.items():
                    api_args[key] = hex(int.from_bytes(value, 'little'))

            case APIHook.API_RegCreateKeyEx | APIHook.API_RegOpenKeyEx:
                api_args["hKey"] = hex(int.from_bytes(api_args["hKey"], 'little'))
                api_args["lpSubKey"] = api_args["lpSubKey"].decode(encoding="ansi")
            case APIHook.API_RegSetValueEx:
                api_args["hKey"] = hex(int.from_bytes(api_args["hKey"], 'little'))
                api_args["lpValueName"] = api_args["lpValueName"].decode(encoding="ansi")
                api_args["dwType"] = hex(int.from_bytes(api_args["dwType"], 'little'))
                api_args["cbData"] = hex(int.from_bytes(api_args["cbData"], 'little'))
            case APIHook.API_RegCloseKey:
                api_args["hKey"] = hex(int.from_bytes(api_args["hKey"], 'little'))
            case APIHook.API_RegDeleteValue:
                api_args["hKey"] = hex(int.from_bytes(api_args["hKey"], 'little'))
                api_args["lpValueName"] = api_args["lpValueName"].decode(encoding="ansi")

            case APIHook.API_send | APIHook.API_recv | APIHook.API_sendto\
                | APIHook.API_recvfrom | APIHook.API_connect:
                api_args["local"] = api_args["local"].decode(encoding="ansi")
                api_args["remote"] = api_args["remote"].decode(encoding="ansi")
                sock_type = int.from_bytes(api_args["sock_type"], 'little')
                match sock_type:
                    case 1:
                        api_args["sock_type"] = "SOCK_STREAM"
                    case 2:
                        api_args["sock_type"] = "SOCK_DGRAM"
                    case 3:
                        api_args["sock_type"] = "SOCK_RAW"
                    case 4:
                        api_args["sock_type"] = "SOCK_RDM"
                    case 5:
                        api_args["sock_type"] = "SOCK_SEQPACKET"
            case _:
                pass
                return
        match api_rule:
            case 0:
                api_rule = "Allow"
            case 1:
                api_rule = "Reject"
            case 2: # Request
                msg = f"## {api_name}\n\n"
                for arg_name, arg_value in api_args.items():
                    msg += f"{arg_name}: \t{arg_value}\n\n"
                if (self.api_request(msg)):
                    api_rule = "Allow"
                    self.__api_reply(True, addr)
                else:
                    api_rule = "Reject"
                    self.__api_reply(False, addr)
            case 3: # nerver here
                pass
            case _:
                pass

        # 添加记录
        record = {"api_args":api_args, "name":api_name, "time":api_time, "rule":api_rule}
        proc.records.append(record)

        item = QTreeWidgetItem(None, 
        [api_name, f"[{proc.name}]  {time.ctime(api_time)}", api_rule])
        # 添加参数到记录item中
        for key, value in api_args.items():
            QTreeWidgetItem(item, [key, str(value)])

        self.__record_list.append({"proc":proc, "args_str":f"{api_name}{api_args}", "treeListItem":item})
        if (proc != self.__selected_proc and self.__config_mode != CONFIG_OVERVIEW):
            item.setHidden(True)
        self.recordTreeWidget.addTopLevelItem(item)