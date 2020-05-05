# Pyback
FUD python2 backdoor  

# Features
1- AES encryption available (pycrypto doesnt work as it should with windows so use for linux only)  
2- screenshot  
3-check sandbox and VM (VM check only for windows, using wmi module)  
4- download/upload files  
5- dump clipboard  
6- run a fork bomb on victim machine, just for fun:)  
7- persistance using REGKEY (windows only)  
8- client or server connection wait (one time only, no reconnecting yet)  

# Usage
pip install -r requirments.txt  

attacker side:  
./listener.py

victim side:  
./backdoor.py  

# Tips
when using pyinstaller for windows executable generation, use the unencrypted backdoor as pycrypto doesn't work on windows.  
also pyinstaller will encrease the detection rate.  
backdoor doesnt auto-activate the persistance module for better evation chance, if you want to change that simply uncomment
the self.persistance() line in backdoor file.  
for list of commnads type 'h' in the listener console.   

# ToDo
credential dumping features  
linux persistance  



# PoC
![Image description](https://github.com/7h3w4lk3r/pyback/blob/master/poc.png)  
  
# Contact  
Email: bl4ckr4z3r@gmail.com  
Telegram ID: @w4lk3r1998

