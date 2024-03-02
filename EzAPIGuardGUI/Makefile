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
    venv\Scripts\activate.bat && python -m PyQt6.uic.pyuic uics/MainWindow.ui -o Scripts/ui/__MainWindow.py
    venv\Scripts\activate.bat && python -m PyQt6.uic.pyuic uics/ProcessView.ui -o Scripts/ui/__ProcessView.py
    venv\Scripts\activate.bat && python -m PyQt6.uic.pyuic uics/APIRequestDialog.ui -o Scripts/ui/__APIRequestDialog.py
    venv\Scripts\activate.bat && python -m PyQt6.uic.pyuic uics/AboutDialog.ui -o Scripts/ui/__AboutDialog.py
    venv\Scripts\activate.bat && pyinstaller -n EzAPIGuard -y --noconsole main.py
    move /y $(OUT_DIR)\*.dll $(MAKEDIR)\dist\EzAPIGuard
    @if exist "$(ROOT)\output" cmd /c "rmdir /S /Q $(ROOT)\output"
    @if not exist "$(ROOT)\output" mkdir $(ROOT)\output
    @if not exist "$(ROOT)\output\Tests" mkdir $(ROOT)\output\Tests
    move /y $(OUT_DIR)\*.exe $(ROOT)\output\Tests
    move /y $(MAKEDIR)\dist\EzAPIGuard $(ROOT)\output


clean:
    @cd "$(MAKEDIR)"
    @if exist "$(MAKEDIR)\EzAPIGuard.spec" del /q $(MAKEDIR)\EzAPIGuard.spec
    @if exist "$(MAKEDIR)\build" cmd /c "rmdir /S /Q $(MAKEDIR)\build"
    @if exist "$(ROOT)\output" cmd /c "rmdir /S /Q $(ROOT)\output"