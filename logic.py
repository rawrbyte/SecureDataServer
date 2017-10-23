# https://pypi.python.org/pypi/simple-rbac
import rbac.acl
import time
from datetime import datetime
from passlib.hash import pbkdf2_sha256

# RIGHTS CONSTANTS
READ     = "read"
WRITE    = "write"
APPEND   = "append"
DELEGATE = "delegate"

class Principal:
    # Handles all <prim_cmd>
    r = rbac.acl.Registry()

    def __init__(self, name, password):
        # Create Principal
        self.setName(name)
        self.setPassword(password)
        self.dataDict = {}
        self.r.add_role(name)
        self.loginAttempt = 0
        self.lockStatus = False
        self.lockDate = None

    def setName(self, name):
        self._name = name

    def getName(self):
        return self._name

    def setPassword(self, password):
        hash = pbkdf2_sha256.hash(password)
        self._password = hash

    def getPassword(self):
        return self._password

    def resetLoginAttempt(self):
        self.loginAttempt = 0

    def incrementLoginAttempt(self):
        self.loginAttempt += 1

    def getLoginAttempt(self):
        return self.loginAttempt

    def getLockStatus(self):
        return self.lockStatus

    def setData(self, var, d):
        self.dataDict.update({var : d})
        self.r.add_resource(var)

    def getData(self, var):
        return self.dataDict.get(var)

    def checkLockStatus(self):
        if self.loginAttempt < 4:
            return False
        else:
            if self.lockDate is None:
                self.lockStatus = True
                self.lockDate = datetime.now()
            else:
                lockTime = (datetime.now() - self.lockDate).total_seconds()
                if lockTime > 600:
                    self.lockStatus = False
                    self.loginAttempt = 0
                    return False
                else:
                    return True

    def setRights(self, principal, action, resource):
        # Set Delegation
        self.r.allow(principal, action, resource)

    def checkPermission(self, principal, action, resource):
        if self.r.is_allowed(principal, action, resource):
            print("SUCCESS")
        else:
            print("DENIED")

def verifyPass(principal, password):
    # Handles <prog>
    if pbkdf2_sha256.verify(password, principal.getPassword()) and principal.getLockStatus() is False:
        principal.resetLoginAttempt()
        print("Correct Password")
    else:
        if principal.checkLockStatus():
            print("Too many wrong attempts. Please try again after 10 minutes")
        else: 
            principal.incrementLoginAttempt()
            print("Wrong password!")

def main():
    print("Creating principals: pOne, pTwo, pThree. Printing names and hashed passwords.")
    pOne = Principal("pOne", "1")
    print(pOne.getName())
    print(pOne.getPassword())

    pTwo = Principal("pTwo", "2")
    print(pTwo.getName())
    print(pTwo.getPassword())

    pThree = Principal("pThree", "3")
    print(pThree.getName())
    print(pThree.getPassword())

    print("\nSet and get data")
    pOne.setData("intro_msg", "Hello")
    print(pOne.getData("intro_msg"))
    pTwo.setData("middle_msg", "World")
    print(pTwo.getData("middle_msg"))
    pThree.setData("end_msg", ":)")
    print(pThree.getData("end_msg"))

    print("\nSet rights: pTwo is allowed to READ pOne's intro_msg, then verify with pTwo and pThree")
    pOne.setRights(pTwo.getName(), READ, "intro_msg")
    pOne.checkPermission(pTwo.getName(), READ, "intro_msg")
    pOne.checkPermission(pThree.getName(), READ, "intro_msg")

    print("\nVerify passwords of pOne")
    verifyPass(pOne, "1")
    verifyPass(pOne, "WRONG_PASS")
    verifyPass(pOne, "WRONG_PASS")
    verifyPass(pOne, "WRONG_PASS")
    verifyPass(pOne, "WRONG_PASS")
    verifyPass(pOne, "WRONG_PASS")
    verifyPass(pOne, "WRONG_PASS")
    verifyPass(pOne, "WRONG_PASS")



if __name__ == "__main__":
    main()