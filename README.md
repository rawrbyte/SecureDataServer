# SecureDataServer

# Libraries used:
- Lark

Install Lark:
pip install lark-parser

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