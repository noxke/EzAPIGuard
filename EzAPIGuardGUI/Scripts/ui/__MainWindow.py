# Form implementation generated from reading ui file 'uics/MainWindow.ui'
#
# Created by: PyQt6 UI code generator 6.6.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1280, 720)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMouseTracking(False)
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.centralwidget)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.horizontalLayout_1 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_1.setSizeConstraint(QtWidgets.QLayout.SizeConstraint.SetDefaultConstraint)
        self.horizontalLayout_1.setObjectName("horizontalLayout_1")
        self.processListVerticalLayout = QtWidgets.QVBoxLayout()
        self.processListVerticalLayout.setObjectName("processListVerticalLayout")
        self.processListLabel = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.processListLabel.setFont(font)
        self.processListLabel.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.processListLabel.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.processListLabel.setLineWidth(1)
        self.processListLabel.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        self.processListLabel.setScaledContents(False)
        self.processListLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.processListLabel.setWordWrap(False)
        self.processListLabel.setObjectName("processListLabel")
        self.processListVerticalLayout.addWidget(self.processListLabel)
        self.processListTreeWidget = QtWidgets.QTreeWidget(parent=self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.processListTreeWidget.sizePolicy().hasHeightForWidth())
        self.processListTreeWidget.setSizePolicy(sizePolicy)
        self.processListTreeWidget.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.processListTreeWidget.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.processListTreeWidget.setAllColumnsShowFocus(False)
        self.processListTreeWidget.setObjectName("processListTreeWidget")
        self.processListTreeWidget.header().setCascadingSectionResizes(True)
        self.processListTreeWidget.header().setDefaultSectionSize(64)
        self.processListTreeWidget.header().setHighlightSections(False)
        self.processListTreeWidget.header().setMinimumSectionSize(32)
        self.processListTreeWidget.header().setSortIndicatorShown(True)
        self.processListVerticalLayout.addWidget(self.processListTreeWidget)
        self.horizontalLayout_1.addLayout(self.processListVerticalLayout)
        self.horizontalLayout.addLayout(self.horizontalLayout_1)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.recordVerticalLayout = QtWidgets.QVBoxLayout()
        self.recordVerticalLayout.setObjectName("recordVerticalLayout")
        self.recordLabel = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.recordLabel.setFont(font)
        self.recordLabel.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.recordLabel.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.recordLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.recordLabel.setObjectName("recordLabel")
        self.recordVerticalLayout.addWidget(self.recordLabel)
        self.recordTreeWidget = QtWidgets.QTreeWidget(parent=self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.recordTreeWidget.sizePolicy().hasHeightForWidth())
        self.recordTreeWidget.setSizePolicy(sizePolicy)
        self.recordTreeWidget.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.recordTreeWidget.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.recordTreeWidget.setDragEnabled(True)
        self.recordTreeWidget.setTextElideMode(QtCore.Qt.TextElideMode.ElideRight)
        self.recordTreeWidget.setWordWrap(False)
        self.recordTreeWidget.setHeaderHidden(False)
        self.recordTreeWidget.setObjectName("recordTreeWidget")
        self.recordTreeWidget.header().setVisible(True)
        self.recordTreeWidget.header().setCascadingSectionResizes(True)
        self.recordTreeWidget.header().setDefaultSectionSize(64)
        self.recordTreeWidget.header().setHighlightSections(False)
        self.recordTreeWidget.header().setMinimumSectionSize(32)
        self.recordTreeWidget.header().setSortIndicatorShown(True)
        self.recordVerticalLayout.addWidget(self.recordTreeWidget)
        self.searchBarHorizontalLayout = QtWidgets.QHBoxLayout()
        self.searchBarHorizontalLayout.setObjectName("searchBarHorizontalLayout")
        self.searchLineEdit = QtWidgets.QLineEdit(parent=self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.searchLineEdit.sizePolicy().hasHeightForWidth())
        self.searchLineEdit.setSizePolicy(sizePolicy)
        self.searchLineEdit.setObjectName("searchLineEdit")
        self.searchBarHorizontalLayout.addWidget(self.searchLineEdit)
        self.searchClearButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.searchClearButton.setObjectName("searchClearButton")
        self.searchBarHorizontalLayout.addWidget(self.searchClearButton)
        self.recordVerticalLayout.addLayout(self.searchBarHorizontalLayout)
        self.horizontalLayout_2.addLayout(self.recordVerticalLayout)
        self.horizontalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.configVerticalLayout = QtWidgets.QVBoxLayout()
        self.configVerticalLayout.setObjectName("configVerticalLayout")
        self.configLabel = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.configLabel.setFont(font)
        self.configLabel.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.configLabel.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.configLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.configLabel.setObjectName("configLabel")
        self.configVerticalLayout.addWidget(self.configLabel)
        self.selectedHorizontalLayout = QtWidgets.QHBoxLayout()
        self.selectedHorizontalLayout.setObjectName("selectedHorizontalLayout")
        self.selectedButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.selectedButton.setCheckable(True)
        self.selectedButton.setObjectName("selectedButton")
        self.selectedHorizontalLayout.addWidget(self.selectedButton)
        self.overviewButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.overviewButton.setCheckable(True)
        self.overviewButton.setObjectName("overviewButton")
        self.selectedHorizontalLayout.addWidget(self.overviewButton)
        self.configVerticalLayout.addLayout(self.selectedHorizontalLayout)
        self.line_2 = QtWidgets.QFrame(parent=self.centralwidget)
        self.line_2.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line_2.setObjectName("line_2")
        self.configVerticalLayout.addWidget(self.line_2)
        self.processNameHorizontalLayout = QtWidgets.QHBoxLayout()
        self.processNameHorizontalLayout.setObjectName("processNameHorizontalLayout")
        self.processNameLabel_ = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.processNameLabel_.setFont(font)
        self.processNameLabel_.setObjectName("processNameLabel_")
        self.processNameHorizontalLayout.addWidget(self.processNameLabel_)
        self.processNameLabel = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.processNameLabel.setFont(font)
        self.processNameLabel.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.processNameLabel.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.processNameLabel.setText("")
        self.processNameLabel.setObjectName("processNameLabel")
        self.processNameHorizontalLayout.addWidget(self.processNameLabel)
        self.processNameHorizontalLayout.setStretch(0, 1)
        self.processNameHorizontalLayout.setStretch(1, 1)
        self.configVerticalLayout.addLayout(self.processNameHorizontalLayout)
        self.line_1 = QtWidgets.QFrame(parent=self.centralwidget)
        self.line_1.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line_1.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line_1.setObjectName("line_1")
        self.configVerticalLayout.addWidget(self.line_1)
        self.configGridLayout = QtWidgets.QGridLayout()
        self.configGridLayout.setObjectName("configGridLayout")
        self.networkRiskLabel = QtWidgets.QLabel(parent=self.centralwidget)
        self.networkRiskLabel.setObjectName("networkRiskLabel")
        self.configGridLayout.addWidget(self.networkRiskLabel, 8, 0, 1, 1)
        self.fileRiskLabel = QtWidgets.QLabel(parent=self.centralwidget)
        self.fileRiskLabel.setObjectName("fileRiskLabel")
        self.configGridLayout.addWidget(self.fileRiskLabel, 5, 0, 1, 1)
        self.apiTypeLabel = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.apiTypeLabel.setFont(font)
        self.apiTypeLabel.setObjectName("apiTypeLabel")
        self.configGridLayout.addWidget(self.apiTypeLabel, 0, 0, 1, 1)
        self.registryLabel = QtWidgets.QLabel(parent=self.centralwidget)
        self.registryLabel.setObjectName("registryLabel")
        self.configGridLayout.addWidget(self.registryLabel, 6, 0, 1, 1)
        self.fileLabel = QtWidgets.QLabel(parent=self.centralwidget)
        self.fileLabel.setObjectName("fileLabel")
        self.configGridLayout.addWidget(self.fileLabel, 4, 0, 1, 1)
        self.registryRiskLabel = QtWidgets.QLabel(parent=self.centralwidget)
        self.registryRiskLabel.setObjectName("registryRiskLabel")
        self.configGridLayout.addWidget(self.registryRiskLabel, 7, 0, 1, 1)
        self.heapRiskLabel = QtWidgets.QLabel(parent=self.centralwidget)
        self.heapRiskLabel.setObjectName("heapRiskLabel")
        self.configGridLayout.addWidget(self.heapRiskLabel, 3, 0, 1, 1)
        self.heapLabel = QtWidgets.QLabel(parent=self.centralwidget)
        self.heapLabel.setObjectName("heapLabel")
        self.configGridLayout.addWidget(self.heapLabel, 2, 0, 1, 1)
        self.registryRule = QtWidgets.QComboBox(parent=self.centralwidget)
        self.registryRule.setObjectName("registryRule")
        self.registryRule.addItem("")
        self.registryRule.addItem("")
        self.registryRule.addItem("")
        self.registryRule.addItem("")
        self.configGridLayout.addWidget(self.registryRule, 6, 1, 1, 1)
        self.registryRiskRule = QtWidgets.QComboBox(parent=self.centralwidget)
        self.registryRiskRule.setObjectName("registryRiskRule")
        self.registryRiskRule.addItem("")
        self.registryRiskRule.addItem("")
        self.registryRiskRule.addItem("")
        self.registryRiskRule.addItem("")
        self.configGridLayout.addWidget(self.registryRiskRule, 7, 1, 1, 1)
        self.heapRule = QtWidgets.QComboBox(parent=self.centralwidget)
        self.heapRule.setObjectName("heapRule")
        self.heapRule.addItem("")
        self.heapRule.addItem("")
        self.heapRule.addItem("")
        self.heapRule.addItem("")
        self.configGridLayout.addWidget(self.heapRule, 2, 1, 1, 1)
        self.networkRiskRule = QtWidgets.QComboBox(parent=self.centralwidget)
        self.networkRiskRule.setObjectName("networkRiskRule")
        self.networkRiskRule.addItem("")
        self.networkRiskRule.addItem("")
        self.networkRiskRule.addItem("")
        self.networkRiskRule.addItem("")
        self.configGridLayout.addWidget(self.networkRiskRule, 8, 1, 1, 1)
        self.fileRiskRule = QtWidgets.QComboBox(parent=self.centralwidget)
        self.fileRiskRule.setObjectName("fileRiskRule")
        self.fileRiskRule.addItem("")
        self.fileRiskRule.addItem("")
        self.fileRiskRule.addItem("")
        self.fileRiskRule.addItem("")
        self.configGridLayout.addWidget(self.fileRiskRule, 5, 1, 1, 1)
        self.label = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.configGridLayout.addWidget(self.label, 0, 1, 1, 1)
        self.heapRiskRule = QtWidgets.QComboBox(parent=self.centralwidget)
        self.heapRiskRule.setObjectName("heapRiskRule")
        self.heapRiskRule.addItem("")
        self.heapRiskRule.addItem("")
        self.heapRiskRule.addItem("")
        self.heapRiskRule.addItem("")
        self.configGridLayout.addWidget(self.heapRiskRule, 3, 1, 1, 1)
        self.countLabel = QtWidgets.QLabel(parent=self.centralwidget)
        self.countLabel.setObjectName("countLabel")
        self.configGridLayout.addWidget(self.countLabel, 0, 2, 1, 1)
        self.fileRule = QtWidgets.QComboBox(parent=self.centralwidget)
        self.fileRule.setObjectName("fileRule")
        self.fileRule.addItem("")
        self.fileRule.addItem("")
        self.fileRule.addItem("")
        self.fileRule.addItem("")
        self.configGridLayout.addWidget(self.fileRule, 4, 1, 1, 1)
        self.fileCnt = QtWidgets.QLabel(parent=self.centralwidget)
        self.fileCnt.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.fileCnt.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.fileCnt.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.fileCnt.setObjectName("fileCnt")
        self.configGridLayout.addWidget(self.fileCnt, 4, 2, 1, 1)
        self.heapRiskCnt = QtWidgets.QLabel(parent=self.centralwidget)
        self.heapRiskCnt.setLayoutDirection(QtCore.Qt.LayoutDirection.LeftToRight)
        self.heapRiskCnt.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.heapRiskCnt.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.heapRiskCnt.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.heapRiskCnt.setObjectName("heapRiskCnt")
        self.configGridLayout.addWidget(self.heapRiskCnt, 3, 2, 1, 1)
        self.heapCnt = QtWidgets.QLabel(parent=self.centralwidget)
        self.heapCnt.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.heapCnt.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.heapCnt.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.heapCnt.setObjectName("heapCnt")
        self.configGridLayout.addWidget(self.heapCnt, 2, 2, 1, 1)
        self.registryCnt = QtWidgets.QLabel(parent=self.centralwidget)
        self.registryCnt.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.registryCnt.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.registryCnt.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.registryCnt.setObjectName("registryCnt")
        self.configGridLayout.addWidget(self.registryCnt, 6, 2, 1, 1)
        self.fileRiskCnt = QtWidgets.QLabel(parent=self.centralwidget)
        self.fileRiskCnt.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.fileRiskCnt.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.fileRiskCnt.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.fileRiskCnt.setObjectName("fileRiskCnt")
        self.configGridLayout.addWidget(self.fileRiskCnt, 5, 2, 1, 1)
        self.networkRiskCnt = QtWidgets.QLabel(parent=self.centralwidget)
        self.networkRiskCnt.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.networkRiskCnt.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.networkRiskCnt.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.networkRiskCnt.setObjectName("networkRiskCnt")
        self.configGridLayout.addWidget(self.networkRiskCnt, 8, 2, 1, 1)
        self.registryRiskCnt = QtWidgets.QLabel(parent=self.centralwidget)
        self.registryRiskCnt.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.registryRiskCnt.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.registryRiskCnt.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.registryRiskCnt.setObjectName("registryRiskCnt")
        self.configGridLayout.addWidget(self.registryRiskCnt, 7, 2, 1, 1)
        self.configGridLayout.setColumnStretch(0, 2)
        self.configVerticalLayout.addLayout(self.configGridLayout)
        self.line_3 = QtWidgets.QFrame(parent=self.centralwidget)
        self.line_3.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        self.line_3.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.line_3.setObjectName("line_3")
        self.configVerticalLayout.addWidget(self.line_3)
        self.hookStatusGridLayout = QtWidgets.QGridLayout()
        self.hookStatusGridLayout.setObjectName("hookStatusGridLayout")
        self.hookDisableButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.hookDisableButton.setObjectName("hookDisableButton")
        self.hookStatusGridLayout.addWidget(self.hookDisableButton, 4, 0, 1, 1)
        self.hookEnableButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.hookEnableButton.setObjectName("hookEnableButton")
        self.hookStatusGridLayout.addWidget(self.hookEnableButton, 2, 0, 1, 1)
        self.warningCnt = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.warningCnt.setFont(font)
        self.warningCnt.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.warningCnt.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.warningCnt.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.warningCnt.setObjectName("warningCnt")
        self.hookStatusGridLayout.addWidget(self.warningCnt, 4, 2, 1, 1)
        self.hookedCnt = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.hookedCnt.setFont(font)
        self.hookedCnt.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.hookedCnt.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.hookedCnt.setAlignment(QtCore.Qt.AlignmentFlag.AlignRight|QtCore.Qt.AlignmentFlag.AlignTrailing|QtCore.Qt.AlignmentFlag.AlignVCenter)
        self.hookedCnt.setObjectName("hookedCnt")
        self.hookStatusGridLayout.addWidget(self.hookedCnt, 2, 2, 1, 1)
        self.hookUnloadButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.hookUnloadButton.setObjectName("hookUnloadButton")
        self.hookStatusGridLayout.addWidget(self.hookUnloadButton, 2, 1, 1, 1)
        self.killProcButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.killProcButton.setObjectName("killProcButton")
        self.hookStatusGridLayout.addWidget(self.killProcButton, 4, 1, 1, 1)
        self.configVerticalLayout.addLayout(self.hookStatusGridLayout)
        self.loginfoLabel = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.loginfoLabel.setFont(font)
        self.loginfoLabel.setFrameShape(QtWidgets.QFrame.Shape.Panel)
        self.loginfoLabel.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        self.loginfoLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.loginfoLabel.setObjectName("loginfoLabel")
        self.configVerticalLayout.addWidget(self.loginfoLabel)
        self.loginfoTextBrowser = QtWidgets.QTextBrowser(parent=self.centralwidget)
        self.loginfoTextBrowser.setObjectName("loginfoTextBrowser")
        self.configVerticalLayout.addWidget(self.loginfoTextBrowser)
        self.horizontalLayout_3.addLayout(self.configVerticalLayout)
        self.horizontalLayout.addLayout(self.horizontalLayout_3)
        self.horizontalLayout.setStretch(1, 12)
        MainWindow.setCentralWidget(self.centralwidget)
        self.toolBar = QtWidgets.QToolBar(parent=MainWindow)
        self.toolBar.setObjectName("toolBar")
        MainWindow.addToolBar(QtCore.Qt.ToolBarArea.TopToolBarArea, self.toolBar)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1280, 26))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(parent=self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuProcess = QtWidgets.QMenu(parent=self.menubar)
        self.menuProcess.setObjectName("menuProcess")
        self.menuView = QtWidgets.QMenu(parent=self.menubar)
        self.menuView.setObjectName("menuView")
        self.menuAbout = QtWidgets.QMenu(parent=self.menubar)
        self.menuAbout.setObjectName("menuAbout")
        MainWindow.setMenuBar(self.menubar)
        self.actionAttach = QtGui.QAction(parent=MainWindow)
        self.actionAttach.setObjectName("actionAttach")
        self.actionRun = QtGui.QAction(parent=MainWindow)
        self.actionRun.setObjectName("actionRun")
        self.viewReset = QtGui.QAction(parent=MainWindow)
        self.viewReset.setObjectName("viewReset")
        self.processAttach = QtGui.QAction(parent=MainWindow)
        self.processAttach.setObjectName("processAttach")
        self.processRun = QtGui.QAction(parent=MainWindow)
        self.processRun.setObjectName("processRun")
        self.recordSave = QtGui.QAction(parent=MainWindow)
        self.recordSave.setObjectName("recordSave")
        self.recordLoad = QtGui.QAction(parent=MainWindow)
        self.recordLoad.setObjectName("recordLoad")
        self.actionPort = QtGui.QAction(parent=MainWindow)
        self.actionPort.setObjectName("actionPort")
        self.actionAbout = QtGui.QAction(parent=MainWindow)
        self.actionAbout.setObjectName("actionAbout")
        self.menuFile.addAction(self.recordSave)
        self.menuFile.addAction(self.recordLoad)
        self.menuProcess.addAction(self.processAttach)
        self.menuProcess.addAction(self.processRun)
        self.menuView.addAction(self.viewReset)
        self.menuAbout.addAction(self.actionAbout)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuProcess.menuAction())
        self.menubar.addAction(self.menuView.menuAction())
        self.menubar.addAction(self.menuAbout.menuAction())

        self.retranslateUi(MainWindow)
        self.searchLineEdit.textChanged['QString'].connect(MainWindow.record_search_filter) # type: ignore
        self.searchClearButton.clicked.connect(self.searchLineEdit.clear) # type: ignore
        self.processListTreeWidget.itemSelectionChanged.connect(MainWindow.select_process) # type: ignore
        self.hookEnableButton.clicked.connect(MainWindow.hook_enable) # type: ignore
        self.hookDisableButton.clicked.connect(MainWindow.hook_disable) # type: ignore
        self.hookUnloadButton.clicked.connect(MainWindow.hook_unload) # type: ignore
        self.selectedButton.clicked.connect(MainWindow.view_selected) # type: ignore
        self.overviewButton.clicked.connect(MainWindow.view_overview) # type: ignore
        self.heapRule.currentIndexChanged['int'].connect(MainWindow.rules_config) # type: ignore
        self.heapRiskRule.currentIndexChanged['int'].connect(MainWindow.rules_config) # type: ignore
        self.fileRule.currentIndexChanged['int'].connect(MainWindow.rules_config) # type: ignore
        self.fileRiskRule.currentIndexChanged['int'].connect(MainWindow.rules_config) # type: ignore
        self.registryRule.currentIndexChanged['int'].connect(MainWindow.rules_config) # type: ignore
        self.registryRiskRule.currentIndexChanged['int'].connect(MainWindow.rules_config) # type: ignore
        self.networkRiskRule.currentIndexChanged['int'].connect(MainWindow.rules_config) # type: ignore
        self.killProcButton.clicked.connect(MainWindow.kill_process) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "EzAPIGuard"))
        self.processListLabel.setText(_translate("MainWindow", "Process List"))
        self.processListTreeWidget.setSortingEnabled(True)
        self.processListTreeWidget.headerItem().setText(0, _translate("MainWindow", "Process"))
        self.processListTreeWidget.headerItem().setText(1, _translate("MainWindow", "PID"))
        self.processListTreeWidget.headerItem().setText(2, _translate("MainWindow", "Status"))
        self.recordLabel.setText(_translate("MainWindow", "API Hook Records"))
        self.recordTreeWidget.setSortingEnabled(True)
        self.recordTreeWidget.headerItem().setText(0, _translate("MainWindow", "ApiName"))
        self.recordTreeWidget.headerItem().setText(1, _translate("MainWindow", "Details"))
        self.recordTreeWidget.headerItem().setText(2, _translate("MainWindow", "Status"))
        self.searchLineEdit.setPlaceholderText(_translate("MainWindow", "Search"))
        self.searchClearButton.setText(_translate("MainWindow", "Clear"))
        self.configLabel.setText(_translate("MainWindow", "Config Selected"))
        self.selectedButton.setText(_translate("MainWindow", "Selected"))
        self.overviewButton.setText(_translate("MainWindow", "Overview"))
        self.processNameLabel_.setText(_translate("MainWindow", "ProcessName:"))
        self.networkRiskLabel.setText(_translate("MainWindow", "NetworkRisk"))
        self.fileRiskLabel.setText(_translate("MainWindow", "FileRisk"))
        self.apiTypeLabel.setText(_translate("MainWindow", "ApiType"))
        self.registryLabel.setText(_translate("MainWindow", "Registry"))
        self.fileLabel.setText(_translate("MainWindow", "File"))
        self.registryRiskLabel.setText(_translate("MainWindow", "RegistryRisk"))
        self.heapRiskLabel.setText(_translate("MainWindow", "HeapRisk"))
        self.heapLabel.setText(_translate("MainWindow", "Heap"))
        self.registryRule.setItemText(0, _translate("MainWindow", "Allow"))
        self.registryRule.setItemText(1, _translate("MainWindow", "Reject"))
        self.registryRule.setItemText(2, _translate("MainWindow", "Request"))
        self.registryRule.setItemText(3, _translate("MainWindow", "UnHook"))
        self.registryRiskRule.setItemText(0, _translate("MainWindow", "Allow"))
        self.registryRiskRule.setItemText(1, _translate("MainWindow", "Reject"))
        self.registryRiskRule.setItemText(2, _translate("MainWindow", "Request"))
        self.registryRiskRule.setItemText(3, _translate("MainWindow", "UnHook"))
        self.heapRule.setItemText(0, _translate("MainWindow", "Allow"))
        self.heapRule.setItemText(1, _translate("MainWindow", "Reject"))
        self.heapRule.setItemText(2, _translate("MainWindow", "Request"))
        self.heapRule.setItemText(3, _translate("MainWindow", "UnHook"))
        self.networkRiskRule.setItemText(0, _translate("MainWindow", "Allow"))
        self.networkRiskRule.setItemText(1, _translate("MainWindow", "Reject"))
        self.networkRiskRule.setItemText(2, _translate("MainWindow", "Request"))
        self.networkRiskRule.setItemText(3, _translate("MainWindow", "UnHook"))
        self.fileRiskRule.setItemText(0, _translate("MainWindow", "Allow"))
        self.fileRiskRule.setItemText(1, _translate("MainWindow", "Reject"))
        self.fileRiskRule.setItemText(2, _translate("MainWindow", "Request"))
        self.fileRiskRule.setItemText(3, _translate("MainWindow", "UnHook"))
        self.label.setText(_translate("MainWindow", "Rule"))
        self.heapRiskRule.setItemText(0, _translate("MainWindow", "Allow"))
        self.heapRiskRule.setItemText(1, _translate("MainWindow", "Reject"))
        self.heapRiskRule.setItemText(2, _translate("MainWindow", "Request"))
        self.heapRiskRule.setItemText(3, _translate("MainWindow", "UnHook"))
        self.countLabel.setText(_translate("MainWindow", "Count"))
        self.fileRule.setItemText(0, _translate("MainWindow", "Allow"))
        self.fileRule.setItemText(1, _translate("MainWindow", "Reject"))
        self.fileRule.setItemText(2, _translate("MainWindow", "Request"))
        self.fileRule.setItemText(3, _translate("MainWindow", "UnHook"))
        self.fileCnt.setText(_translate("MainWindow", "0"))
        self.heapRiskCnt.setText(_translate("MainWindow", "0"))
        self.heapCnt.setText(_translate("MainWindow", "0"))
        self.registryCnt.setText(_translate("MainWindow", "0"))
        self.fileRiskCnt.setText(_translate("MainWindow", "0"))
        self.networkRiskCnt.setText(_translate("MainWindow", "0"))
        self.registryRiskCnt.setText(_translate("MainWindow", "0"))
        self.hookDisableButton.setText(_translate("MainWindow", "HookDisable"))
        self.hookEnableButton.setText(_translate("MainWindow", "HookEnable"))
        self.warningCnt.setText(_translate("MainWindow", "0 Warning"))
        self.hookedCnt.setText(_translate("MainWindow", "0 Hooked"))
        self.hookUnloadButton.setText(_translate("MainWindow", "HookUnload"))
        self.killProcButton.setText(_translate("MainWindow", "KillProc"))
        self.loginfoLabel.setText(_translate("MainWindow", "Log Info"))
        self.loginfoTextBrowser.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.toolBar.setWindowTitle(_translate("MainWindow", "toolBar"))
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuProcess.setTitle(_translate("MainWindow", "Process"))
        self.menuView.setTitle(_translate("MainWindow", "View"))
        self.menuAbout.setTitle(_translate("MainWindow", "About"))
        self.actionAttach.setText(_translate("MainWindow", "Attach"))
        self.actionRun.setText(_translate("MainWindow", "Run"))
        self.viewReset.setText(_translate("MainWindow", "Reset"))
        self.processAttach.setText(_translate("MainWindow", "Attach"))
        self.processRun.setText(_translate("MainWindow", "Run"))
        self.recordSave.setText(_translate("MainWindow", "Save"))
        self.recordLoad.setText(_translate("MainWindow", "Load"))
        self.actionPort.setText(_translate("MainWindow", "Port"))
        self.actionAbout.setText(_translate("MainWindow", "About EzAPIGuard"))
