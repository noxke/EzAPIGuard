# Makefile for EzAPIGuard

ROOT = ..
!if "$(PLANTFORM)" == "x64"
OUT_DIR=$(ROOT)\$(PLANTFORM)\$(CONFIG)
!else if "$(PLANTFORM)" == "win32"
OUT_DIR=$(ROOT)\$(CONFIG)
!endif

all:
    @cd "$(MAKEDIR)"
    @if not exist "venv" python -m venv venv && venv\Scripts\activate.bat && pip install -r requirments.txt
    venv\Scripts\activate.bat && pyinstaller -n EzAPIGuard -y main.py
    move /y $(OUT_DIR)\*.dll $(MAKEDIR)\dist\EzAPIGuard
    @if not exist "$(ROOT)\output" cmd /c "mkdir $(ROOT)\output"
    move /y $(MAKEDIR)\dist\EzAPIGuard $(ROOT)\output


clean:
    @cd "$(MAKEDIR)"
    @if exist "$(MAKEDIR)\main.spec" del /q $(MAKEDIR)\main.spec
    @if exist "$(MAKEDIR)\EzAPIGuard.spec" del /q $(MAKEDIR)\EzAPIGuard.spec
    @if exist "$(MAKEDIR)\build" cmd /c "rmdir /S /Q $(MAKEDIR)\build"
    @if exist "$(ROOT)\output" cmd /c "rmdir /S /Q $(ROOT)\output"