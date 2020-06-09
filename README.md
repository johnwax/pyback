# Pyback   
FUD cross-platform python2 backdoor  

# Features  
1- linux and windows post-exploitation enumeration  
2- run powershell commands and scripts  
3- screenshot  
4-check sandbox and VM (VM check only for windows, using wmi module)  
5- download/upload files  
6- dump clipboard  
7- run a fork bomb on victim machine, just for fun:)  
8- persistance using REGKEY (windows only)  
9- client or server connection wait (one time only, no reconnecting yet)  
10- dump hashes with ntds and reg save methods ( files should be manually downloaded ) 

# Usage
`pip install -r requirments.txt`  

change the port and ip or DNS in both listener.py and backdoor.py files  

attacker side:  
`./listener.py`

victim side:  
`./backdoor.py`  

# Tips
pyinstaller will encrease the detection rate. use this version only:   
`pip install pyinstaller==3.1.1`  

to use upload functionality you should put the target file in the same directory as the listener.py file  

backdoor doesnt auto-activate the persistence module for better evation chance, if you want to change that simply uncomment  
the self.persistance() line in backdoor file.  

for list of commnads type 'help' in the listener console when connected to the backdoor.   

tkinter most be installed by default, otherwise install it with:  
`apt install python-tk`  

the `enum` command results will be saved in the listener directory. to see colored output use `cat enum*.txt`  

# PoC  
  using pure python code:  
   
![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/poc.png)  
  
  using pyinstaller version 3.1.1:  

![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/image.png) 

  
# Contact  
Email: bl4ckr4z3r@gmail.com  
Telegram ID: @w4lk3r1998

