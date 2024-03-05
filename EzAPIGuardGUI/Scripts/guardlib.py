# guardlib.py
# EzGuardLib接口

import os
import shutil
import ctypes
import pefile
import psutil
import socketserver
from threading import Thread

main_path = os.getcwd()

guard_dll_x86 = "GuardDll_x86.dll"
guard_dll_x64 = "GuardDll_x64.dll"
guard_lib = "EzGuardLib.dll"
export_server_port = b"serverPort"

RECV_TIMEOUT = 1
RETRY_TIMES = 3

class APIHook():
    """一些常量"""
    MSG_NONE = 0  # 空数据包
    MSG_HELLO = 1 # hello数据包 传输pid信息
    MSG_ACK = 2   # 确认数据包
    MSG_HOOKED = 10   # api hook数据包
    MSG_REPLY = 11    # hooked回复包
    MSG_ATTACH = 20   # 配置hook指定api
    MSG_DETACH = 21   # 配置取消hook指定api
    MSG_CONFIG = 22   # api配置包来判断是否放行或者拦截api
    MSG_ENABLE = 250    # 启用hook
    MSG_DISABLE = 251   # 禁用hook
    MSG_UNLOAD = 252    # 卸载dll
    MSG_KILL = 255      # 关闭进程

    API_NONE = 0  # 空定义 不需要实现
    API_MessageBoxA = 1
    API_MessageBoxW = 2
    API_CreateFile = 3
    API_ReadFile = 4
    API_WriteFile = 5
    API_HeapCreate = 6
    API_HeapDestroy = 7
    API_HeapFree = 8
    API_HeapAlloc = 9
    API_RegCreateKeyEx = 10
    API_RegSetValueEx = 11
    API_RegCloseKey = 12
    API_RegOpenKeyEx = 13
    API_RegDeleteValue = 14
    API_send = 15
    API_recv = 16
    API_sendto = 17
    API_recvfrom = 18
    API_connect = 19

    udp_msg_struct = "H H I Q"
    api_hooked_msg_struct = "H H I Q H H"
    api_config_msg_struct = "H H I Q ?"

class ApiAnalyzer():
    """EzGuardLib分析器接口 每个进程对应一个分析器"""
    def __init__(self):
        self.dll = ctypes.CDLL(os.path.join(main_path, guard_lib))


class Injector():
    """dll注入器接口"""
    def __init__(self):
        self.__injected_dll_x86 = os.path.join(main_path, guard_dll_x86)
        self.__injected_dll_x64 = os.path.join(main_path, guard_dll_x64)
        self.dll = ctypes.CDLL(os.path.join(main_path, guard_lib))
        self.__init_lib()
        self.__inject_pid = self.dll.InjectByPID
        self.__inject_pid.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
        self.__inject_pid.restype = ctypes.c_bool
        self.__run_exe = self.dll.RunInject
        self.__run_exe.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.__run_exe.restypes = ctypes.c_uint32

    def __init_lib(self):
        """初始化EzGuardLib中的两个kernel32.dll rva"""
        lla_rva_x86 = 0
        lla_rva_x64 = 0
        system_drive = os.environ['SYSTEMDRIVE']

        k32_x86_path = os.path.join(system_drive, "/Windows/SysWOW64/kernel32.dll")
        k32_x86_pe = pefile.PE(k32_x86_path)
        export_table = k32_x86_pe.DIRECTORY_ENTRY_EXPORT
        for export in export_table.symbols:
            if (export.name == b"LoadLibraryA"):
                lla_rva_x86 = export.address
                break
        k32_x86_pe.close()
        rva_p = ctypes.cast(self.dll.LoadLibraryArva86, ctypes.POINTER(ctypes.c_uint64))
        rva_p.contents.value = lla_rva_x86

        k32_x64_path = os.path.join(system_drive, "/Windows/System32/kernel32.dll")
        k32_x64_pe = pefile.PE(k32_x64_path)
        export_table = k32_x64_pe.DIRECTORY_ENTRY_EXPORT
        for export in export_table.symbols:
            if (export.name == b"LoadLibraryA"):
                lla_rva_x64 = export.address
                break
        k32_x64_pe.close()
        rva_p = ctypes.cast(self.dll.LoadLibraryArva64, ctypes.POINTER(ctypes.c_uint64))
        rva_p.contents.value = lla_rva_x64

    def init_dll(self, port:int):
        """初始化注入dll patch端口"""
        temp_dir = os.path.join(main_path, "temp")
        if (os.path.exists(temp_dir)):
            shutil.rmtree(temp_dir)
        os.mkdir(temp_dir)
        pe = pefile.PE(self.__injected_dll_x86)
        self.__injected_dll_x86 = os.path.join(temp_dir, guard_dll_x86)
        # 导出表
        export_table = pe.DIRECTORY_ENTRY_EXPORT
        # 遍历导出表中的符号
        for export in export_table.symbols:
            if (export.name == export_server_port):
                rva = export.address
                # patch端口
                pe.set_word_at_rva(rva, port)
                break
        pe.write(self.__injected_dll_x86)
        pe.close()
        pe = pefile.PE(self.__injected_dll_x64)
        self.__injected_dll_x64 = os.path.join(temp_dir, guard_dll_x64)
        # 导出表
        export_table = pe.DIRECTORY_ENTRY_EXPORT
        # 遍历导出表中的符号
        for export in export_table.symbols:
            if (export.name == export_server_port):
                rva = export.address
                # patch端口
                pe.set_word_at_rva(rva, port & 0xFFFF)
                break
        pe.write(self.__injected_dll_x64)
        pe.close()

    def inject_pid(self, pid:int)->bool:
        """注入dll到目标程序"""
        bits = 0
        if (not psutil.pid_exists(pid)):
            return False
        process = psutil.Process(pid)
        pe_path = process.exe()
        pe = pefile.PE(pe_path)
        if pe.FILE_HEADER.Machine == 0x14c:
            bits = 32
        elif pe.FILE_HEADER.Machine == 0x8664:
            bits = 64
        pe.close()
        if (bits == 32):
            return self.__inject_pid(ctypes.c_uint32(pid), self.__injected_dll_x86.encode(encoding="ansi"))
        elif (bits == 64):
            return self.__inject_pid(ctypes.c_uint32(pid), self.__injected_dll_x64.encode(encoding="ansi"))
        else:
            return False

    def run_exe(self, exe_path:str)->int:
        """运行exe程序并注入dll"""
        bits = 0
        pe = pefile.PE(exe_path)
        if pe.FILE_HEADER.Machine == 0x14c:
            bits = 32
        elif pe.FILE_HEADER.Machine == 0x8664:
            bits = 64
        pe.close()
        if (bits == 32):
            return self.__run_exe(exe_path.encode(encoding="ansi"), None, self.__injected_dll_x86.encode(encoding="ansi"))
        elif (bits == 64):
            return self.__run_exe(exe_path.encode(encoding="ansi"), None, self.__injected_dll_x64.encode(encoding="ansi"))
        else:
            return 0

    def kill_process(self, pid:int)->bool:
        """关闭目标进程"""
        if (not psutil.pid_exists(pid)):
            return False
        process = psutil.Process(pid)
        try:
            process = psutil.Process(pid)
            process.terminate()  # 发送 SIGTERM 信号终止进程
        except:
            return False
        return True


class UdpSocketServer():
    """socket服务端"""

    def __init__(self, Address=("127.0.0.1", 0), RequestHandler=None):
        self.server_addr = Address
        self.req_handler = RequestHandler
        if (RequestHandler == None):
            self.req_handler = self.udp_handle
        self.server = socketserver.UDPServer(self.server_addr, self.req_handler)
        self.server_addr = self.server.server_address
        self.server.timeout = RECV_TIMEOUT
        self.retry_times = RETRY_TIMES
        self.__handle_status:bool = False
        self.handler_thread:Thread = None

    def send_to(self, addr, data):
        """发送udp数据包"""
        self.server.socket.sendto(data, addr)

    def __handler_thread(self):
        """接收线程"""
        while (self.__handle_status == True):
            self.server.handle_request()

    def start_handler_thread(self):
        """启动接收线程"""
        self.stop_handler_thread()
        self.__handle_status = True
        self.handler_thread = Thread(target=self.__handler_thread)
        self.handler_thread.start()


    def stop_handler_thread(self):
        """结束接收线程"""
        if (self.handler_thread != None):
            try:
                self.__handle_status = False
                self.handler_thread.join()
            except:
                pass

    def udp_handle(self, request, client_address, server):
        """udp消息处理器"""
        data, socket = request
        # 处理接收到的 UDP 数据
        print("({} : {}".format(client_address, data))