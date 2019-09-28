import json
import sys
from pexpect import pxssh, spawn, expect
import pexpect
from time import sleep
from subprocess import call, Popen, PIPE, STDOUT

with open('./boot/config/config.json') as json_data:
    config = json.load(json_data)

def assignUser(server):
    if (not 'username' in server):
        server['username']=config['username']
    if ( ('publickeyfile' in config) and (len(config['publickeyfile'])) and (not 'publickeyfile' in server) and (not 'password' in server) ):
        server['publickeyfile']=config['publickeyfile']
    if (not 'password' in server):
        server['password']=config['password']
    if (not 'port' in server):
        server['port']=None

def parseArgs(args=sys.argv):
    del args[0]
    parsed = []
    while (len(args)):
        if (args[0].find('-')==0):
            parsed.append( {'k':args[0].lower(),'v':[], 'hard':False, 'alt':[]} )
        else:
            servs=[]
            match=False
            for server in config['servers']:
                if (args[0]==server['name'] or args[0]==server['address']):
                    match=[server]
                else:
                    if (server['name'].find(args[0])!=-1):
                        servs.append(server)
            if (args[0].lower()=='hard'):
                parsed[len(parsed)-1]['hard']=True
            elif ((not match) and (not len(servs))):
                parsed[len(parsed)-1]['alt'].append(args[0])
            if (match):
                parsed[len(parsed)-1]['v']+=match
            else:
                parsed[len(parsed)-1]['v']+=servs
        del args[0]
    return parsed

def init(config = config):

    if not 'main' in config:
        config['main']=[]
    if not 'masternodes' in config:
        config['masternodes']=[]
    if not 'stakingnodes' in config:
        config['stakingnodes']=[]
    if not 'wallets' in config:
        config['wallets']=[]

    assignUser(config['main'])

    for node in config['masternodes']:
        assignUser(node)

    for node in config['stakingnodes']:
        assignUser(node)

    for node in config['wallets']:
        assignUser(node)

    config['servers']=[config['main']]+config['masternodes']+config['stakingnodes']+config['wallets']

    if (not 'serveroption' in config):
        config['serveroption']=""
    else:
        config['serveroption']=' '+config['serveroption']+' '

    return config

def ssh(server):
    print '\033[0;36;48m  Connecting to '+server['name']+' ('+server['address']+')...\033[0m'
    connect = pxssh.pxssh()
    try:
        if ('publickeyfile' in server):
            connectionString = server['username']+'@'+server['address']
            connect.login (connectionString, None, port=server['port'], ssh_key=server['publickeyfile'])
        else:
            print '\033[0;36;48m     with:   '+server['username']+'  :  '+server['password']+'\033[0m'
            connect.login (server['address'], server['username'], server['password'])#, port=server['port'])
        print '\033[1;32;40m   Connected.\033[0m'
        return connect
    except pxssh.ExceptionPxssh, err:
        print str(err)
        print '\033[1;31;40m   Could not connect to: \033[0m'+server['name']
        return 0

def disconnect(connect):
    print '\033[0;36;48m   Disconnecting... \n\n\033[0m'
    connect.logout()

def send(sshConnect, command):
    try:
        sshConnect.sendline(command)
        sshConnect.prompt()    
        print sshConnect.before
        response = sshConnect.before.replace('\r','')
        response = response.split('\n')  
        del response[0]
        return response  
    except pxssh.ExceptionPxssh, err:
        print str(err)
        return 0

#send file from local machine to remote server
def sendFile(server, sourcestr, deststr, options=''):
    print 'Sending '+sourcestr+' to '+server['name']
    if ('publickeyfile' in server):
        print 'scp '+options+' '+sourcestr+' '+server['username']+'@'+server['address']+':'+deststr
        process = spawn('scp -i '+server['publickeyfile']+' '+options+' '+sourcestr+' '+server['username']+'@'+server['address']+':'+deststr)
        process.timeout=12000
        sleep(10)
        print process.before
        print process.buffer
        print process.after
    else:
        try:
            print 'scp '+options+' '+sourcestr+' '+server['username']+'@'+server['address']+':'+deststr
            process = spawn('scp '+options+' '+sourcestr+' '+server['username']+'@'+server['address']+':'+deststr)
            sleep(2)
            print process.before
            print process.buffer
            print process.after
            response = process.expect('password:.*', timeout=5)
            process.sendline(server['password']+'\n')
            #process.timeout=12000
            #cpl = process.compile_pattern_list(['denied.*','refused.*'])
            sleep(2)
            print process.before
            print process.buffer
            print process.after
            #denied = process.expect('denied.*', timeout=3)
            if (process.after.find('denied')==-1):
                print "logged in"
                eof = process.expect('eta', timeout=12000)
                
                eof = process.expect(pexpect.EOF, timeout=12000)
            else:
                print "Could not complete transfer"
            print process.before
            print process.buffer
            print process.after
            process.terminate(True)
        except pexpect.TIMEOUT, err:
            print 'Timeout'
            pass
        except pexpect.EOF, err:
            print str(err)
            pass
        finally:
            pass








config = init()
args = parseArgs()
