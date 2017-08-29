#!/usr/bin/env python


import requests, os, sys, subprocess, base64, time
import csv
import argparse
import re
import socket
import urllib2


__author__='Anthr@X'

true_socket = socket.socket
preferredcountries=['JP','KR','CA','TW','SG']
blacklist=[]

def getServers():
    api='http://www.vpngate.net/api/iphone/'
    rt=requests.get(api)
    while rt.status_code!=200:
        print 'API error, retrying...'
        rt=requests.get(api)
        time.sleep(1);
    servers = []
    for server_string in rt.text.replace("\r", "").split('\n')[2:-2]:  
        (HostName, IP, Score, Ping, Speed, CountryLong, CountryShort, NumVpnSessions, 
Uptime, TotalUsers, TotalTraffic, LogType, Operator, Message, 
OpenVPN_ConfigData_Base64)=server_string.split(',')
        try:
            bw=int(Speed)
        except:
            bw=0

        try:
            ss=int(NumVpnSessions)+1
        except:
            ss=-1

        try:
            p=int(Ping)
        except:
            p=300

        cscore= (bw / ss) / p

        server = {
                'HostName': HostName,
                'IP': IP,
                'Score': int(Score),
                'Ping': Ping,
                'Speed': Speed,
                'CountryLong': CountryLong,
                'CountryShort': CountryShort,
                'NumVpnSessions': NumVpnSessions,
                'Uptime': Uptime,
                'TotalUsers': TotalUsers,
                'TotalTraffic': TotalTraffic,
                'LogType': LogType,
                'Operator': Operator,
                'Message': Message,
                'OpenVPN_ConfigData_Base64': OpenVPN_ConfigData_Base64,
                'cscore': cscore
                }
        if CountryShort not in preferredcountries:
            continue

        servers.append(server)
    return servers


def getCountries(server):
    return set((server['CountryShort'], server['CountryLong']) for server in servers)

def printCountries(countries):
    print "Countries:"
    for country in countries:
        print country[0], country[1]

def getTopServers(servers,length=5):
    newlist = sorted(servers, key=lambda k: k['Score'],reverse=True)
    return newlist[0:length] 


def startvpn(server):
    fn='vpnserver1.conf'

    print "\nLaunching VPN...",server['IP'],server['CountryShort'],server['Score']
    

    f = open(fn, 'w')
    f.write('''
verb 3
writepid /var/run/openvpn_client1.pid
script-security 3
keepalive 10 60
ping-timer-rem
persist-tun
persist-key
up /usr/local/sbin/ovpn-linkup
down /usr/local/sbin/ovpn-linkdown
engine cryptodev
client
management /var/etc/openvpn/client1.sock unix
resolv-retry infinite
route-noexec
        ''')
    f.write(base64.b64decode(server['OpenVPN_ConfigData_Base64']))

    f.close()

    proc = subprocess.Popen(['openvpn','--connect-retry-max','2','--config', 
fn],stdout=subprocess.PIPE)

    regex=re.compile(r'\/sbin\/ifconfig (tun\d+|tap\d+) (\d+\.\d+\.\d+\.\d+)')

    srcip=None
    while True:
        output = proc.stdout.readline().strip()
        print output
        res=regex.search(output)
        if res!=None:
            try:
                srcip=res.group(2)
                dev=res.group(1)
            except:
                pass
        if output == '' and proc.poll() is not None:
            return False,False,False
        if output:
            if 'SIGUSR1' in output:
                print 'Connection failed. Terminating'
                proc.terminate()
                print 'Terminated.'
                return False,False,False
            if 'Initialization Sequence Completed' in output:
                try:
                    dev
                except:
                    continue
                break
            if 'AUTH_FAILED' in output:
                blacklist.append(server['IP'])
                print 'Fake server, adding to blacklist.'
                return False,False,False
         
    return proc,srcip,dev

def autostartvpn():
    allservers=getServers()
    topservers=getTopServers(allservers)
    for srv in topservers:
        if srv['IP'] in blacklist:
            print 'IP in blacklist, skipping'
            continue
        os.system('ifconfig tun0 destroy')
        (proc,srcip,dev) = startvpn(srv)
        print srcip,dev
        if proc!=False:
            print 'Connect Success!',srv['IP'],srv['CountryShort'],dev
            return proc,srcip
    print 'No server available'
    exit()

def make_bound_socket(source_ip):
    def bound_socket(*a, **k):
        sock = true_socket(*a, **k)
        sock.bind((source_ip, 0))
        return sock
    return bound_socket

def testconn(srcip):
    try:
      socket.socket=make_bound_socket(srcip)
    except Exception as e:
      print 'Unable to bind to source ip',srcip,e
      return False
    try:
      print 'Public IP', urllib2.urlopen('https://api.ipify.org').read()
      return True
    except Exception as e:
      print e
      return False


if __name__=="__main__":
    proc,srcip=autostartvpn()
    while True:
        if testconn(srcip)==False:
            proc.kill()
            while proc.poll()==None:
                time.sleep(1)
                print 'Waiting for openvpn process to quit'
            proc,srcip=autostartvpn()
        time.sleep(5)

    print 'VPN disconnected.'






