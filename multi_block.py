import hashlib
import os
from scapy.all import *
from netfilterqueue import NetfilterQueue

blockList = open('./hashed.txt', 'r').read().split('\n')


def iptables_init():
    cmd  = "sudo iptables -A OUTPUT -p tcp -j NFQUEUE\n"
    cmd += "sudo iptables -A INPUT -p tcp -j NFQUEUE\n"
    os.system(cmd)


def iptables_restore():
    cmd = "sudo iptables -F\n"
    os.system(cmd)


def isHttpRequest(data):
    headers = data.splitlines()
    method = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']
    for name in method:
        if headers[0][0:len(name)] == name:
            return 1
        return 0


def search(name):
    s, e = 0, len(blockList)-1
    while(s<=e):
        m = (s + e)//2
        if blockList[m] == name:
            return 1
        elif blockList[m] > name:
            e = m-1
        else:
            s = m+1
    print 'Cannot Found'
    return 0


def cb(pkt):
    spkt = IP(pkt.get_payload())
    #spkt.show()
    if spkt.getlayer(Raw) and isHttpRequest(spkt.payload.load):
        rawData = spkt.payload.load
        hostName = rawData.split('Host: ')[1].split('\r\n')[0]
        print "[+]Target: %s", hostName[4:]
        hashName = hashlib.sha256(hostName[4:]).hexdigest()
        if search(hashName):
            print "[+]Block %s!!", hostName
            pkt.drop()
        pkt.accept()
    else:
        pkt.accept()


if __name__ == "__main__":
    iptables_init()
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, cb)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        iptables_restore()
        nfqueue.unbind()
        os._exit(1)

