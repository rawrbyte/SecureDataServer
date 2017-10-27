# SecureDataServer

# Libraries used:
- Lark

logic.py
--------

Simple RBAC  
https://github.com/tonyseek/simple-rbac
~~~~~~~~~~~
Using pip to install does not work.
Please manually install by downloading the package.
After download, navigate to setup.py and remove .decode() from line 7
Then use: python3 setup.py install
~~~~~~~~~~~

PassLib  
https://passlib.readthedocs.io/en/stable/
~~~~~~~~~~~
Used for encryption/decryption of passwords  
python3 -m pip install passlib
~~~~~~~~~~~

Primitive Commands (<prim_cmd>)  
~~~~~~~~~~~
create principal p s
  def __init__(self, name, password)
  
change password p s
  def setPassword(self, password)
  
set x = <expr>
  def setData(self, var, d)
  
append to x with <expr>
  def append(self)
  
local x = <expr>
  def local(self)
  
foreach y in x replacewith <expr>
  def forEach(self)
  
set delegation <tgt> q <right> -> p
  def setRights(self, principal, action, resource)
  
delete delegation <tgt> q <right> -> p
  def deleteRights(self)
  
default delegator = p
  def defaultRights(self)
~~~~~~~~~~~