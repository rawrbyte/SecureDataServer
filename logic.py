# https://pypi.python.org/pypi/simple-rbac
import rbac.acl
from passlib.hash import pbkdf2_sha256

# RIGHTS CONSTANTS
READ     = "read"
WRITE    = "write"
APPEND   = "append"
DELEGATE = "delegate"

# Admin?
isAdmin = False
adminPass = "pass" # ./server [PASSWORD]

# Accounts
accounts = set()

class Variable:
    def __init__(self, val):
        self.varValue = val

    def __copy__(self):
        copiedVar = type(self)()
        copiedVar.__dict__.update(self.__dict__)
        return copiedVar

class Principal:
    # Handles all <prim_cmd>
    r = rbac.acl.Registry()

    def __init__(self, name, password):
        # Create Principal
        # as principal p password s do
        if name in accounts:
            print("{\"status\":\"DENIED\"}")
            return
        self.setName(name)
        self.setPassword(password)
        self.dataDict = {}
        self.localVars = {}
        self.r.add_role(name)
        print("{\"status\":\"CREATE_PRINCIPAL\"}")

    def setName(self, name):
        self._name = name

    def getName(self):
        return self._name

    def setPassword(self, password):
        hash = pbkdf2_sha256.hash(password)
        self._password = hash
        print("{\"status\":\"CHANGE_PASSWORD\"}")

    def getPassword(self):
        return self._password

    def setData(self, var, d):
        # set s = <expr>
        tmp = Variable(d)
        self.dataDict.update({var : tmp})
        self.r.add_resource(var)
        print("{\"status\":\"SET\"}")

    def getData(self, var):
        if var in self.dataDict:
            return self.dataDict.get(var).varValue
        else:
            return self.localVars.get(var).varValue

    def setRights(self, principal, action, resource):
        # Set Delegation
        self.r.allow(principal, action, resource)
        print("{\"status\":\"SET_DELEGATION\"}")

    def deleteRights(self):
        print("{\"status\":\"DELETE_DELEGATION\"}")

    def defaultRights(self):
        print("{\"status\":\"DEFAULT_DELEGATOR\"}")

    def checkPermission(self, principal, action, resource):
        if self.r.is_allowed(principal, action, resource):
            print("{\"status\":\"SUCCESS\"}")
        else:
            print("{\"status\":\"DENIED\"}")

    def append(self, var, d):
        if type(d) is str:
            tmp = Variable(self.getData(var) + d)
            self.dataDict.update({var:tmp})
            self.r.add_resource(var)
        elif type(d) is dict:
            t = list(self.dataDict.get(var).varValue)
            t.append(d)
            tmp = Variable(t)
            self.dataDict.update({var:tmp})
            self.r.add_resource(var)
        print("{\"status\":\"APPEND\"}")

    def local(self, var, d):
        if d in self.dataDict:
            t = self.dataDict.get(d).varValue
            tmp = Variable(t)
            self.localVars.update({var: tmp})
            self.r.add_resource(var)
        else:
            tmp = Variable(d)
            self.localVars.update({var : tmp})
            self.r.add_resource(var)
        print("{\"status\":\"LOCAL\"}")

    def forEach(self, y, x, expr):

        print("{\"status\":\"FOREACH\"}")

    def output(self):
        print("{\"status\":\"RETURNING\"}")

    def terminate(self):
        self.localVars = {}

def verifyPass(principal, password):
    # Handles <prog>
    if pbkdf2_sha256.verify(password, principal.getPassword()):
        print("{\"status\":\"SUCCESS\"}")
    else:
        print("{\"status\":\"DENIED\"}")

def main():
    print("Create Admin account")
    print("Add account to accounts set. Set isAdmin to True")
    print("-----")
    admin = Principal("admin", adminPass)
    list = ['asdf', 'asfd']
    admin.setData("x", "hello")

    l1 = ['asdf', '1234']
    l2 = 3452345

    print("\nTest for Appending String")
    admin.setData("varTest", "hello")
    print(admin.getData("varTest"))
    admin.append("varTest", "123412341234")
    print(admin.getData("varTest"))

    print("\nTest for Appending List")
    admin.setData("records", [])
    print(admin.getData("records"))

    r1 = {"name":"mike", "date":"1-1-90"}
    r2 = {"name":"dave", "date":"1-1-85"}
    admin.append("records", r1)
    admin.append("records", r2)
    print(admin.getData("records"))

    print("\nTest local")
    admin.local("names", "records")
    print(admin.getData("names"))

    print("\nSet Data Test")
    admin.setData("x", l1)
    print(admin.getData("x"))

    admin.setData("y", admin.getData("x"))
    print(admin.getData("y"))

    admin.setData("x", l2)
    print(admin.getData("x"))

    accounts.add(admin.getName())
    if admin.getName() in accounts:
        isAdmin = True

    print("\nUsing Admin account, create principals: pOne, pTwo, pThree.")
    print("Print names and hashed passwords.")
    print("-----")
    if isAdmin:
        pOne = Principal("pOne", "1")
        accounts.add(pOne.getName())
        print(pOne.getName())
        print(pOne.getPassword())

    if isAdmin:
        pTwo = Principal("pTwo", "2")
        accounts.add(pTwo.getName())
        print(pTwo.getName())
        print(pTwo.getPassword())

    if isAdmin:
        pThree = Principal("pThree", "3")
        accounts.add(pThree.getName())
        print(pThree.getName())
        print(pThree.getPassword())

    if isAdmin:
        print("Creating duplicate account name")
        pThree2 = Principal("pThree", "3")

    print("\nSet and get data")
    print("-----")
    pOne.setData("intro_msg", "Hello")
    print(pOne.getData("intro_msg"))
    pTwo.setData("middle_msg", "World")
    print(pTwo.getData("middle_msg"))
    pThree.setData("end_msg", ":)")
    print(pThree.getData("end_msg"))

    print("\nSet rights: pTwo is allowed to READ pOne's intro_msg, then verify with pTwo and pThree")
    print("-----")
    pOne.setRights(pTwo.getName(), READ, "intro_msg")
    pOne.checkPermission(pTwo.getName(), READ, "intro_msg")
    pOne.checkPermission(pThree.getName(), READ, "intro_msg")

    print("\nVerify passwords of pOne")
    print("-----")
    verifyPass(pOne, "1")
    verifyPass(pOne, "$pbkdf2-sha256$29000$B.AcY.w9p9T6PwfgXMuZkw$tNWzC3BcBkK92Wq0hKCaOcvIINZ4W1pkZ/fnMSzcXlM")
    verifyPass(pOne, "WRONG_PASS")

if __name__ == "__main__":
    main()