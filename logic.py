import rbac.acl
import rbac.context
from passlib.hash import pbkdf2_sha256

# Admin
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
    #r = rbac.acl.Registry()
    r = rbac.acl.Registry()
    context = rbac.context.IdentityContext(r)

    def __init__(self, name, password):
        # Create Principal
        # as principal p password s do
        if name in accounts:
            res = {"status": "DENIED"}
            print(res)
            return
        self.setName(name)
        hash = pbkdf2_sha256.hash(password)
        self._password = hash
        self.dataDict = {}
        self.localVars = {}
        tmprole = self.r.add_role(name)
        self.context.set_roles_loader(tmprole)
        res = {"status": "CREATE_PRINCIPAL"}
        print(res)

    def setName(self, name):
        self._name = name

    def getName(self):
        return self._name

    def setPassword(self, password):
        hash = pbkdf2_sha256.hash(password)
        self._password = hash
        res = {"status": "CHANGE_PASSWORD"}
        print(res)

    def getPassword(self):
        return self._password

    def setData(self, var, d):
        # set s = <expr>
        tmp = Variable(d)
        self.dataDict.update({var : tmp})
        self.r.add_resource(var)
        res = {"status": "SET"}
        print(res)

    def getData(self, var):
        if var in self.dataDict:
            return self.dataDict.get(var).varValue
        else:
            return self.localVars.get(var).varValue

    def setRights(self, principal, action, resource):
        if principal == "all":
            for name in accounts:
                self.r.allow(name, action, resource)
        else:
            self.r.allow(principal, action, resource)
        res = {"status": "SET_DELEGATION"}
        print(res)

    def deleteRights(self, principal, action, resource):
        if principal == "all":
            for name in accounts:
                self.r.deny(name, action, resource)
        else:
            self.r.deny(principal, action, resource)
        res = {"status": "DELETE_DELEGATION"}
        print(res)

    def defaultRights(self):
        res = {"status": "DEFAULT_DELEGATOR"}
        print(res)

    def checkPermission(self, principal, action, resource):
        if self.r.is_allowed(principal, action, resource):
            res = {"status":"SUCCESS"}
            print(res)
        else:
            res = {"status":"DENIED"}
            print(res)

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
        res = {"status":"APPEND"}
        print(res)

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
        res = {"status":"LOCAL"}
        print(res)

    def forEach(self, iterator, sequence, expression):
        seq = self.getData(sequence)
        expr = expression.split(".")
        if expr[0] == iterator:
            for i,s in enumerate(seq):
                seq[i] = s.get(expr[1])
        if sequence in self.dataDict:
            tmp = Variable(seq)
            self.dataDict.update({sequence: tmp})
            self.r.add_resource(sequence)
        else:
            tmp = Variable(seq)
            self.localVars.update({sequence: tmp})
            self.r.add_resource(sequence)
        res = {"status":"FOREACH"}
        print(res)

    def cmd_return(self, expr):
        val = self.getData(expr)
        res = {"status":"RETURNING", "output":val}
        print(res)

    def terminate(self):
        self.localVars = {}

    def cmd_exit(self):
        if self._name == 'admin':
            res = {"status":"EXITING"}
            print(res)
            exit(0)
            # Terminate the client connection
            # Halts with return code 0
        else:
            res = {"status": "DENIED"}
            print(res)

def verifyPass(principal, password):
    # Handles <prog>
    if pbkdf2_sha256.verify(password, principal.getPassword()):
        res = {"status":"SUCCESS"}
        print(res)
    else:
        res = {"stats":"DENIED"}
        print(res)

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

    print("\nFor Each Test")
    admin.forEach("rec", "names", "rec.name")
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
    pOne.setRights(pTwo.getName(), "read", "intro_msg")
    pOne.checkPermission(pTwo.getName(), "read", "intro_msg")
    pOne.checkPermission(pThree.getName(), "read", "intro_msg")

    print("\nSet Rights to 'all' now")
    pOne.setRights("all", "read", "intro_msg")
    pOne.checkPermission(pTwo.getName(), "read", "intro_msg")
    pOne.checkPermission(pThree.getName(), "read", "intro_msg")
    print("\nNow we remove pThree's rights to read")
    pOne.deleteRights(pThree.getName(), "read", "intro_msg")
    pOne.checkPermission(pThree.getName(), "read", "intro_msg")


    print("\nVerify passwords of pOne")
    print("-----")
    verifyPass(pOne, "1")
    verifyPass(pOne, "$pbkdf2-sha256$29000$B.AcY.w9p9T6PwfgXMuZkw$tNWzC3BcBkK92Wq0hKCaOcvIINZ4W1pkZ/fnMSzcXlM")
    verifyPass(pOne, "WRONG_PASS")

    print("\nReturning and Exiting")
    admin.cmd_return("records")
    pOne.cmd_exit()
    admin.cmd_exit()

if __name__ == "__main__":
    main()