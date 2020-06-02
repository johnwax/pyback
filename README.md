# Pyback
FUD python2 backdoor  

# Features  
1- screenshot  
2-check sandbox and VM (VM check only for windows, using wmi module)  
3- download/upload files  
4- dump clipboard  
5- run a fork bomb on victim machine, just for fun:)  
6- persistance using REGKEY (windows only)  
7- client or server connection wait (one time only, no reconnecting yet)  

# Usage
`pip install -r requirments.txt`  

attacker side:  
`./listener.py`

victim side:  
`./backdoor.py`  

# Tips
pyinstaller will encrease the detection rate.  

`pip install pyinstaller==3.1.1`  

backdoor doesnt auto-activate the persistance module for better evation chance, if you want to change that simply uncomment
the self.persistance() line in backdoor file.  
for list of commnads type 'h' in the listener console.   
tkinter most be installed by default, otherwise install it with:  
`apt install python-tk`  

# PoC
![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/poc.png)  
  
# Contact  
Email: bl4ckr4z3r@gmail.com  
Telegram ID: @w4lk3r1998

