# guardlib.py
# EzGuardLib接口

import ctypes
import pefile

guard_dll_x86 = "GuardDll_x86.dll"
guard_dll_x64 = "GuardDll_x64.dll"
export_server_port = b"serverPort"