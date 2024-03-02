# EzAPIGuard 界面main

from Scripts.ui import MainWindow
from PyQt6.QtWidgets import QApplication
import sys

app = QApplication(sys.argv)
window = MainWindow.Ui_MainWindow()
window.show()
sys.exit(app.exec())
