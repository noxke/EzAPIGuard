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
    venv\Scripts\activate.bat && pyinstaller -n EzAPIGuard -y --noconsole main.py
    @if not exist "$(ROOT)\output" mkdir $(ROOT)\output
    move /y $(MAKEDIR)\dist\EzAPIGuard $(ROOT)\output
    @cd "$(ROOT)\output"
    @cmd -c "del *.exp *.lib *.pdb"
    @cd "$(MAKEDIR)"



clean:
    @cd "$(MAKEDIR)"
    @if exist "$(MAKEDIR)\EzAPIGuard.spec" del /q $(MAKEDIR)\EzAPIGuard.spec
    @if exist "$(ROOT)\output\EzAPIGuard" cmd /c "rmdir /S /Q $(ROOT)\output\EzAPIGuard"
    @echo "build clean"