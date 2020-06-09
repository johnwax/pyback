# Pyback   
FUD cross-platform python2 backdoor  

# Features  
1-  linux and windows post-exploitation enumeration  
2-  run powershell commands and scripts  
3-  spawn an independent powershell session to a remote machine (catch with netcat)  
4-  screenshot  
5-  check sandbox and VM (VM check only for windows, using wmi module)  
6-  download/upload files  
7-  dump clipboard  
8-  run a fork bomb on victim machine, just for fun:)  
9-  persistance using REGKEY (windows only)  
10- client or server connection wait (one time only, no reconnecting yet)  
11- dump hashes with ntds and reg save methods ( files should be manually downloaded ) 

# Usage
`pip install -r requirments.txt`  


tkinter most be installed by default, otherwise install it with:  
`apt install python-tk`  

pyinstaller will encrease the detection rate. use this version only:   
`pip install pyinstaller==3.1.1`  

change the port and ip or DNS in both listener.py and backdoor.py files  

attacker side:  
`./listener.py`

victim side:  
`./backdoor.py`  


for list of commnads type 'help' in the listener console when connected to the backdoor.   

# Tips

. to use upload functionality you should put the target file in the same directory as the listener.py file  
. install rlwrap with `apt install rlwrap` use `rlwrap ./listener.py` to use up and down arrow key for command cycling  
. backdoor doesnt auto-activate the persistence module for better evation chance, if you want to change that simply uncomment  
the self.persistance() line in backdoor file.  
. the `enum` command results will be saved in the listener directory. to see colored output use `cat enum*.txt`  
.spawn function will run a reverse powershell payload on victim machine, you can catch it with `rlwrap nc -nvlp [port]`  

# PoC  
  using pure python code:  
   
![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/poc.png)  
  
  using pyinstaller version 3.1.1:  

![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/image.png) 

  
# Contact  
Email: bl4ckr4z3r@gmail.com  
Telegram ID: @w4lk3r1998

