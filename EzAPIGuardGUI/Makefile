# Makefile for EzAPIGuard

ROOT = ..
!if "$(PLATFORM)" == "x64"
OUT_DIR=$(ROOT)\$(PLATFORM)\$(CONFIG)
!else if "$(PLATFORM)" == "x86"
OUT_DIR=$(ROOT)\$(CONFIG)
!endif

all:
    @cd "$(MAKEDIR)"
    @if not exist "venv" python -m venv venv && venv\Scripts\activate.bat && pip install -r requirments.txt
    venv\Scripts\activate.bat && python -m PyQt6.uic.pyuic uics/MainWindow.ui -o Scripts/ui/__MainWindow.py
    venv\Scripts\activate.bat && python -m PyQt6.uic.pyuic uics/ProcessView.ui -o Scripts/ui/__ProcessView.py
    venv\Scripts\activate.bat && python -m PyQt6.uic.pyuic uics/APIRequestDialog.ui -o Scripts/ui/__APIRequestDialog.py
    venv\Scripts\activate.bat && python -m PyQt6.uic.pyuic uics/AboutDialog.ui -o Scripts/ui/__AboutDialog.py
    venv\Scripts\activate.bat && pyinstaller -n EzAPIGuard -y --paths Scripts main.py
    @if not exist "$(ROOT)\output" mkdir $(ROOT)\output
    @if not exist "$(ROOT)\output\EzAPIGuard" mkdir $(ROOT)\output\EzAPIGuard
    @cd "$(ROOT)\output\EzAPIGuard"
    @if exist "_internal" cmd /c "rmdir /S /Q _internal"
    @if exist "EzAPIGuard.exe" cmd /c "del EzAPIGuard.exe"
    @cd "$(MAKEDIR)"
    move /Y $(MAKEDIR)\dist\EzAPIGuard\EzAPIGuard.exe $(ROOT)\output\EzAPIGuard
    move /Y $(MAKEDIR)\dist\EzAPIGuard\_internal $(ROOT)\output\EzAPIGuard



clean:
    @cd "$(MAKEDIR)"
    @if exist "$(MAKEDIR)\EzAPIGuard.spec" del /q $(MAKEDIR)\EzAPIGuard.spec
    @if exist "$(ROOT)\output\EzAPIGuard" cmd /c "rmdir /S /Q $(ROOT)\output\EzAPIGuard"
    @echo "build clean"