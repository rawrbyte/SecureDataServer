from logic import Principal
from logic import Variable
from logic import verifyPass

from logic import accounts
from logic import isAdmin
from logic import adminPass

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