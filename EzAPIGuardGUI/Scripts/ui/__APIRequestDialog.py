# Form implementation generated from reading ui file 'uics/APIRequestDialog.ui'
#
# Created by: PyQt6 UI code generator 6.6.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(480, 320)
        self.verticalLayout = QtWidgets.QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.textBrowser = QtWidgets.QTextBrowser(parent=Dialog)
        self.textBrowser.setObjectName("textBrowser")
        self.verticalLayout.addWidget(self.textBrowser)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.allowButton = QtWidgets.QPushButton(parent=Dialog)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.allowButton.sizePolicy().hasHeightForWidth())
        self.allowButton.setSizePolicy(sizePolicy)
        self.allowButton.setObjectName("allowButton")
        self.horizontalLayout.addWidget(self.allowButton)
        self.rejectButton = QtWidgets.QPushButton(parent=Dialog)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.rejectButton.sizePolicy().hasHeightForWidth())
        self.rejectButton.setSizePolicy(sizePolicy)
        self.rejectButton.setObjectName("rejectButton")
        self.horizontalLayout.addWidget(self.rejectButton)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(Dialog)
        self.allowButton.clicked.connect(Dialog.accept) # type: ignore
        self.rejectButton.clicked.connect(Dialog.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "APIRequest"))
        self.allowButton.setText(_translate("Dialog", "Allow"))
        self.rejectButton.setText(_translate("Dialog", "Reject"))
