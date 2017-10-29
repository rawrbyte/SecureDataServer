data = {'all':None, 'append':None, 'as':None, 'change':None, 'create':None, 'default':None, 'delegate':None, 'delegation':None, 'delegator':None, 'delete':None, 'do':None, 'exit':None, 'foreach':None, 'in':None, 'local':None, 'password':None, 'principal':None, 'read':None, 'replacewith':None, 'return':None, 'set':None, 'to':None, 'write':None, '***':None}

def isReserveKeyword(keyword):
    if data.__contains__(keyword):
        return True
    else:
        return False
