# EzAPIGuard 项目开发文档

### 1.项目框架

项目使用 **Visual Studio 2022** 平台开发编译 **(x64)**

图形化界面使用 **Python3.12+PyQt6** 开发

主项目配置文件EzAPIGuard.sln

```bash
EzAPIGuard.sln
- EzAPIGuard
-- Detours
-- EzAPIGuard
-- EzGuardLib
-- GuardDll
- Tests
-- test_example
```

- [Detours](https://github.com/microsoft/Detours)
  
  Detours项目 无需修改

- EzAPIGuard
  
  前端部分 用户界面 交互

- EzGuardLib
  
  主业务逻辑 程序行为分析

- GuardDll
  
  API HOOK

- Tests
  
  待分析样例 每个测试样例新建项目

### 2.GuardDll

> 注入目标程序的dll项目文件

### 3.EzGuardLib

> API调用行为分析库

### 4.EzAPIGuard

> 图形化前端

### 5.Tests

> 待分析样例(此处文档由测试样例负责人编写)

- [ ] TODO @Dongdia
