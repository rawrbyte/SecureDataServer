import rbac.acl
import rbac.context
from passlib.hash import pbkdf2_sha256

# Admin
isAdmin = False
adminPass = "pass" # ./server [PASSWORD]

# Accounts
accounts = set()

####################################

class Principal:
    r = rbac.acl.Registry()
    context = rbac.context.IdentityContext(r)

    def __init__(self, name, password):
        ### CREATE PRINCIPAL ###
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
        ### CHANGE PASSWORD ###
        hash = pbkdf2_sha256.hash(password)
        self._password = hash
        res = {"status": "CHANGE_PASSWORD"}
        print(res)

    def getPassword(self):
        return self._password

    def setData(self, var, d):
        ### SET ###
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

    def checkPermission(self, principal, action, resource):
        if self.r.is_allowed(principal, action, resource):
            res = {"status":"SUCCESS"}
            print(res)
        else:
            res = {"status":"DENIED"}
            print(res)

    def append(self, var, d):
        ### APPEND TO ###
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
        ### LOCAL ###
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
        ### FOREACH ###
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

    def setRights(self, principal, action, resource):
        ### SET DELEGATION ###
        if principal == "all":
            for name in accounts:
                self.r.allow(name, action, resource)
        else:
            self.r.allow(principal, action, resource)
        res = {"status": "SET_DELEGATION"}
        print(res)

    def deleteRights(self, principal, action, resource):
        ### DELETE DELEGATION ###
        if principal == "all":
            for name in accounts:
                self.r.deny(name, action, resource)
        else:
            self.r.deny(principal, action, resource)
        res = {"status": "DELETE_DELEGATION"}
        print(res)

    def defaultRights(self):
        ### DEFAULT DELEGATION ###
        res = {"status": "DEFAULT_DELEGATOR"}
        print(res)

    def cmd_return(self, expr):
        ### RETURN ###
        if "\"" in expr:
            val = expr
        elif '.' in expr:
            e = expr.split('.')
            val = self.getData(expr[0]).get(e[1])
        else:
            val = self.getData(expr)
        res = {"status":"RETURNING", "output":val}
        print(res)

    def cmd_exit(self):
        ### EXIT ###
        if self._name == 'admin':
            res = {"status":"EXITING"}
            print(res)
            exit(0)
            # Terminate the client connection
            # Halts with return code 0
        else:
            res = {"status": "DENIED"}
            print(res)

####################################

class Variable:
    def __init__(self, val):
        self.varValue = val

    def __copy__(self):
        copiedVar = type(self)()
        copiedVar.__dict__.update(self.__dict__)
        return copiedVar

####################################

def verifyPass(principal, password):
    if pbkdf2_sha256.verify(password, principal.getPassword()):
        res = {"status":"SUCCESS"}
        print(res)
    else:
        res = {"stats":"DENIED"}
        print(res)