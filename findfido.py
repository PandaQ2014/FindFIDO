from shutil import copyfile
from multiprocessing import Process
from multiprocessing import Pool
from multiprocessing import freeze_support
import threading
import traceback

from androguard.core.bytecodes.apk import APK
import re
import os
from shutil import copyfile

def copyTo(apkPath,outPutPath,findstr,name):
    if os.path.isdir(outPutPath) == False:
        os.mkdir(outPutPath)
    copyfile(apkPath,outPutPath+name+'.apk')
    outputFile = outPutPath+name+'.txt'
    print(outputFile)
    with open(outputFile,'w') as f:
        for stritem in findstr:
            f.write(stritem+'\n')

def processCheck(apkPath,total,already):
    global rootdir
    unionFingerOutputPath = rootdir+'unionFingerOutput/'
    unionOutputPath = rootdir+'unionOutput/'
    fidoOutputPath = rootdir+'fidoOutput/'
    fidoPermissionOutputPath = rootdir+'fidoPermissionOutput/'
    failedPath=rootdir+'failed/'
    unionfs = r'cn.com.union.fido.ui.finger.FingerActivity'
    #unionfs = r'cn.com.union.fido.service.AuthenticatorService'
    unions = r'union.fido'
    fidos = r'fido'
    try:
        a = APK(apkPath)
    except:
        print('[{0}/{1}]Analysis Failed {2}'.format(already,total,apkPath))
        return
    activities = a.get_activities()
    name = a.get_app_name()
    find = False
    findstr = []
    for activity in activities:
        if activity==unionfs:
            find=True
            findstr.append('[ACTIVITY]'+activity)
    if find:
        print('[{0}/{1}]FIND unionFinger in {2}'.format(already,total,apkPath))
        copyTo(apkPath,unionFingerOutputPath,findstr,name)
        return 


    findstr.clear()
    find=False
    for activity in activities:
        if(re.search(unions,activity.lower())):
            find=True
            findstr.append('[ACTIVITY]'+activity)
    permissions = a.get_permissions()
    for permission in permissions:
        if re.search(unions,permission.lower()):
            find=True,
            findstr.append('[PERMISSION]'+permission)
    services = a.get_services()
    for service in services:
        if re.search(unions,service.lower()):
            find=True,
            findstr.append('[SERVICE]'+service)
    if find:
        print('[{0}/{1}]FIND union in {2}'.format(already,total,apkPath))
        copyTo(apkPath,unionOutputPath,findstr,name)
        return 

    findstr.clear()
    find=False
    for activity in activities:
        if(re.search(fidos,activity.lower())):
            find=True
            findstr.append('[ACTIVITY]'+activity)
    hasFidoPermission = False
    fidoPermission=[]
    for permission in permissions:
        if re.search(fidos,permission.lower()):
            find=True,
            hasFidoPermission=True
            findstr.append('[PERMISSION]'+permission)
            fidoPermission.append('[PERMISSION]'+permission)
    if hasFidoPermission:
        print('[{0}/{1}]FIND fido permission in {2}'.format(already,total,apkPath))
        copyTo(apkPath,fidoPermissionOutputPath,fidoPermission,name)

    for service in services:
        if re.search(fidos,service.lower()):
            find=True,
            findstr.append('[SERVICE]'+service)
    if find:
        print('[{0}/{1}]FIND fido in {2}'.format(already,total,apkPath))
        copyTo(apkPath,fidoOutputPath,findstr,name)
        return 
    print('[{0}/{1}]Nothing FOUND in {2}'.format(already,total,apkPath))


def checkProcessManager():

    while True:
        lock.acquire()
        global already
        global total
        apkPath=''
        try:
            total=len(apkfilesdict)
            for key in apkfilesdict:
                if -1 == apkfilesdict[key][1]:
                    apkPath =  apkfilesdict[key][0]
                    apkfilesdict[key][1] = 0
                    break
        finally:
            lock.release()
        if apkPath != '':
            already=already+1
            freeze_support() 
            t = threading.Thread(target=processCheck,args=(apkPath,total,already))
            t.start()
            t.join()
        else:
            break

if __name__ == "__main__":
    processnum = 6
    #rootdir='H:/apk/钱包/'
    #rootdir='H:/apk/金融/'
    #rootdir='H:/apk/支付/'
    #rootdir='H:/apk/银行/'
    rootdir=r'E:/fido/appcrawler/apkpure/wallet/'
    #rootdir=r'E:/fido/国外app/'
    apkfilesdict = dict()
    total=0
    already=0
    lock = threading.Lock()
    list = os.listdir(rootdir)
    for i in range(0,len(list)):
        path = os.path.join(rootdir,list[i])
        if(os.path.isfile(path)):
            print(path)
            apkfilesdict.update({i: [path,-1]})
    for i in range(processnum):
        t = threading.Thread(target = checkProcessManager)
        t.start()