# guardlib.py
# EzGuardLib接口

import os
import shutil
import ctypes
import pefile
import psutil
from socket import *
from threading import Thread

main_path = os.getcwd()

guard_dll_x86 = "GuardDll_x86.dll"
guard_dll_x64 = "GuardDll_x64.dll"
guard_lib = "EzGuardLib.dll"
export_server_port = b"serverPort"

RECV_TIMEOUT = 1

class APIHook():
    """一些常量"""
    MSG_NONE = 0xC000  # 空数据包
    MSG_HELLO = 0xC001 # hello数据包 传输pid信息
    MSG_ACK = 0xC002   # 确认数据包
    MSG_HOOKED = 0xC010   # api hook数据包
    MSG_REPLY = 0xC011    # hooked回复包
    MSG_ATTACH = 0xC020   # 配置hook指定api
    MSG_DETACH = 0xC021   # 配置取消hook指定api
    MSG_CONFIG = 0xC022   # config配置api hook行为
    MSG_ENABLE = 0xC0F0    # 启用hook
    MSG_DISABLE = 0xC0F1   # 禁用hook
    MSG_UNLOAD = 0xC0F2    # 卸载dll
    MSG_KILL = 0xC0FF      # 关闭进程

    HOOK_API_NUM = 0x50

    API_NONE = 0x00  # 空定义 不需要实现
    API_MessageBoxA = 0x01
    API_MessageBoxW = 0x02
    API_CreateFile = 0x10
    API_ReadFile = 0x11
    API_WriteFile = 0x12
    API_DeleteFile = 0x13
    API_HeapCreate = 0x20
    API_HeapDestroy = 0x21
    API_HeapFree = 0x22
    API_HeapAlloc = 0x23
    API_RegCreateKeyEx = 0x30
    API_RegSetValueEx = 0x31
    API_RegCloseKey = 0x32
    API_RegOpenKeyEx = 0x33
    API_RegDeleteValue = 0x34
    API_send = 0x40
    API_recv = 0x41
    API_sendto = 0x42
    API_recvfrom = 0x43
    API_connect = 0x44

    API_TYPE_NONE = 0
    API_TYPE_FILE = 1
    API_TYPE_HEAP = 2
    API_TYPE_REG = 3
    API_TYPE_NET = 4

    udp_msg_struct = "H H I Q"
    api_hooked_msg_struct = "H H I Q H H H H"
    api_reply_msg_struct = "H H I Q ?"

class ApiAnalyzer():
    """EzGuardLib分析器接口 每个进程对应一个分析器"""
    def __init__(self):
        self.dll = ctypes.CDLL(os.path.join(main_path, guard_lib))
        self.__checker = self.dll.checker
        self.__checker.argtypes = [ctypes.c_char_p, ctypes.c_uint16,\
                                ctypes.c_char_p, ctypes.c_uint16]
        self.__checker.restype = None
    
    def checker(self, data:bytes)->str:
        """分析器接口"""
        ret = ctypes.create_string_buffer(0x100)
        self.__checker(data, len(data), ret, 0x100)
        return bytes(ret).decode(encoding="ansi")


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
        if (pe_path[0] == "\\"):
            # Windows路径就是依托史
            pe_path = "\\" + pe_path
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

    def __init__(self, address=("127.0.0.1", 0), timeout=RECV_TIMEOUT):
        self.server_addr = address
        self.timeout = timeout
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind(self.server_addr)
        self.server_addr = self.sock.getsockname()
        self.sock.settimeout(self.timeout)

    def send_to(self, addr, data):
        """发送udp数据包"""
        self.sock.sendto(data, addr)

    def get_request(self):
        """接收udp"""
        try:
            return self.sock.recvfrom(1024)
        except:
            return (None, None)