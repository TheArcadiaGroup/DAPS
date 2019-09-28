print('Starting script')

from time import sleep
from pexpect import pxssh
import configparser

from config import args, ssh, send, sendFile, disconnect, config as s
from subprocess import call, Popen, PIPE, STDOUT

from getpass import getpass

def status(servers = s['servers']):
    for server in servers:
        print '\033[94m'+server['name']+'   -   '+server['address']+'\033[0m'
        try:
            connect = ssh(server)
            if connect:
                print '\033[92m'+send(connect, 'uptime')+'\033[0m'
                if (s['main']['name']==server['name']): #status checks for main server
                    res = send(connect, "ps -e|grep mongo")
                    if (len(res)>21):
                        print '\033[92m'+res+'\033[0m'
                    else:
                        print '\033[91m'+res+'\nNo mongo service detected\033[0m'
                    res = send(connect, "ps -e|grep node")
                    if (len(res)>21):
                        print '\033[92m'+res+'\033[0m'
                        server['mongodown']=True
                    else:
                        print '\033[91m'+res+'\nNo node service detected\033[0m'
                        server['nodedown']=True
                    send(connect, 'dapscoin-cli '+s['serveroption']+'status')
                    disconnect(connect)
                    call('ping -c 1 '+server['address'], shell=True)
                else:
                    send(connect, 'dapscoin-cli '+s['serveroption']+' masternode status')
                    send(connect, 'dapscoin-cli '+s['serveroption']+' getbalance')
                    disconnect(connect)
                print("\n\n")
                sleep(2)
            else:
                server['down']=True
        except pxssh.ExceptionPxssh, err:
            print str(err)

# def stop():
#     for server in s['servers']:
#         print 'wip'

def stopAllWalletDaemons(servers=s['servers']):
    for server in servers:
        stopAWallet(server)

def stopAWallet(server):
    connect = ssh(server)
    if connect:
        print("Trying to stop daemon:" + server['name'] + "\n")
        send(connect, 'dapscoin-cli '+s['serveroption']+' stop')
        sleep(2)    #wait 2 seconds
        disconnect(connect)

def startStakingWallets(servers, hard=False):
    for server in servers:
        startStakingWallet(server, hard)

def startStakingWallet(server, hard=False):#Main server producing PoW blocks, hard=true meaning to erase block data and restart wallet
    if hard:
        removeBlockchainData(s['main'])
    genStakingnodeConfigs(s['servers'], s['main'])   
    connect = ssh(server)
    if connect:
        send(connect, 'dapscoind '+s['serveroption']+' -daemon')#Start daemon
        sleep(2)    #wait 2 seconds
        if server['address'] == s['main']['address']:#Start generating PoW blocks
            send(connect, 'dapscoin-cli '+s['serveroption']+' setgenerate true 1')
        #if hard:
            #Need to reindex explorer database
        disconnect(connect)

def removeBlockDataFromServers(servers=s['servers']):
    for server in servers:
        removeBlockchainData(server)

def removeBlockchainData(server):
    connect = ssh(server)
    if connect:
        send(connect, 'rm -r * ~/.dapscoin/')
        disconnect(connect)

def startStakingServers(servers=s['servers']):
    for server in servers:
        startStaking(server)

def startStaking(server):
    connect = ssh(server)
    if connect:
        result = send(connect, 'dapscoin-cli '+s['serveroption']+'getstakingstatus')
        print result
        if ((result.find('false')!=-1) or (result.find("couldn't")!=-1)):
            send(connect, 'dapscoind '+s['serveroption']+'stop')
            print "Waiting for 30 seconds..."
            sleep(30)
            send(connect, 'dapscoind '+s['serveroption']+' -daemon')
            send(connect, 'dapscoin-cli '+s['serveroption']+'')
            #unlock wallet
        disconnect(connect)



def masternodeScript(stakingserver, masterservers=s['masterservers']):
    genStakingNodeConfigFileScript(masterservers, stakingserver)
    connect = ssh(stakingserver)
    if connect:
        send(connect, 'dapscoind '+s['serveroption']+'-daemon')
        key = send(connect, 'dapscoin-cli '+s['serveroption']+'masternode genkey')
        if ((key[0].lower().find('not')==-1) and (key[0].lower().find('error')==-1)):
            for server in masterservers:
                genMasternodeConfigFileScript(server, stakingserver, key)
        else:
            print('could not complete process')



def genMasternodeConfigFileScript(masterserver, stakingserver, nodeprivkey):
    dapsConfData = open('boot/config/dapscoin.conf', 'r').read()+'externalip='+masterserver['address']+'\nmasternodeprivkey='+nodeprivkey
    connect = ssh(masterserver)
    if connect:
        send(connect, 'mkdir ~/.dapscoin')
        send(connect, 'touch ~/.dapscoin/dapscoin.conf')
        send(connect, 'echo "'+dapsConfData+'">~/.dapscoin/dapscoin.conf')
        send(connect, 'dapscoin-cli '+s['serveroption']+'-daemon -connect '+stakingserver['address'])
        sleep(5)
        send(connect, 'dapscoin-cli '+s['serveroption']+'masternode genkey')
        disconnect(connect)

def genStakingnodeConfigs(stakingservers=s['stakingnodes'], masterservers=s['masternodes']):
    for server in stakingservers:
        genStakingNodeConfigFileScript(server, masterservers)

def genStakingNodeConfigFileScript(stakingserver, masterservers=s['masternodes']):
    nodes = ''
    for server in masterservers:
        nodes += 'addnode='+server['address']+'\n'
    dapsConfData = open('boot/config/dapscoin.conf', 'r').read() + nodes
    connect = ssh(stakingserver)
    if connect:
        send(connect, 'mkdir ~/.dapscoin')
        send(connect, 'touch ~/.dapscoin/dapscoin.conf')
        send(connect, 'echo "'+dapsConfData+'">~/dapscoin/dapscoin.conf')
        disconnect(connect)

def restartAllWallets(hard=False, masternode=s['masternodes'][0]):#hard restart = erase data and start blockchain from beginning
    stopAllWalletDaemons()
    if hard:
        for server in s['servers']:
            removeBlockchainData(server)
    startStakingWallet(s['main'])
    print('Wait 10s for a number of PoW blocks generated\n')
    sleep(10)

    #start control wallet that controls the first masternode, this assume the machine running
    #this script is running control wallet
    mn1ip = masternode['address']
    if hard:
        #1. Stop control wallet
        p = Popen('dapscoin-cli ' + s['serveroption'] + " stop", shell=True, stdout=PIPE, stderr=STDOUT)
        for line in p.stdout.readlines():
            print line,
        sleep(2)
        #2. Start daemon
        Popen('dapscoind ' + s['serveroption'] + " -daemon", shell=True, stdout=PIPE, stderr=STDOUT)
        sleep(2)

        #3. generate masternodeprivatekey
        p = Popen('dapscoin-cli ' + s['serveroption'] + " masternode genkey", shell=True, stdout=PIPE, stderr=STDOUT)
        lines = p.stdout.readlines()
        mnprivateKey = lines[0]
        mnalias = "masternode1"

        #4. generate account
        p = Popen('dapscoin-cli ' + s['serveroption'] + " getaccountaddress " + mnalias, shell=True, stdout=PIPE, stderr=STDOUT)
        lines = p.stdout.readlines()
        accountAddress = lines[0]

        #5. send 10 000 daps to accountaddress
        txhash = transferFromMainWallet(accountAddress)
        if txhash:
            #check whether the transaction is confirmed
            confirmed = False
            while not confirmed:
                print('Checking tx masternode send confirmation\n')
                p = Popen('dapscoin-cli ' + s['serveroption'] + " masternode outputs", shell=True, stdout=PIPE, stderr=STDOUT)
                lines = p.stdout.readlines()
                if txhash in str(lines):
                    confirmed = True
        else:
            print('cannot send daps to masternode')
            return 0
        
        #6. create masternode.conf file
        mn1port = '53572'
        mnconfPath = '~/.dapscoin/masternode.conf'
        if s['serveroption'] == '-testnet':
            mn1port = '53575'
            mnconfPath = '~/.dapscoin/testnet4/masternode.conf'
        mnconfContent = mnalias + ' ' + mn1ip + ':' + mn1port + ' ' + mnprivateKey + ' ' + txhash + ' 1'
        Popen('echo "' + mnconfContent + '" >' + mnconfPath, shell=True, stdout=PIPE, stderr=STDOUT)

        #7. Start masternode daemon
        startStakingWallet(masternode, hard)
        stopAWallet(masternode)
        nodes = ''
        for server in s['servers']:
            nodes += '\naddnode='+server['address']
        dapsConfData = open('boot/config/dapscoin.conf', 'r').read() + nodes 
        dapsConfData = dapsConfData + '\n' + 'masternode=1\n' + 'externalip=' + mn1ip + '\nmasternodeprivkey=' + mnprivateKey
        mn1Connect=ssh(masternode)
        if mn1Connect:
            send(mn1Connect, 'echo "'+dapsConfData+'">~/dapscoin/dapscoin.conf')
            send(mn1Connect, 'dapscoind '+s['serveroption']+' -daemon')#Start daemon
            disconnect(mn1Connect)

        #8. Start masternode from control wallet
        p = Popen('dapscoin-cli ' + s['serveroption'] + ' startmasternode alias false ' + mnalias, shell=True, stdout=PIPE, stderr=STDOUT)
        lines = p.stdout.readlines()
        if 'Successfully started 1' in str(lines):
            print('Sucessfully start control wallet masternode\n')
        else:
            print('Failed to start control wallet masternode\n')    
            return 0
        
        #9. Start masternode in VPS
        res = send(mn1Connect, 'dapscoin-cli '+s['serveroption']+' startmasternode local false')#Start daemon
        print(res + '\n')

        #10. Start staking nodes...

#transfer funds to specified destination
def transferFromMainWallet(destination, amount = s['coinamount']):
    main = s['main']
    connect = ssh(main)
    if connect:
        response = send(connect, 'dapscoin-cli ' + s['serveroption'] + ' sendtoaddress ' + destination + ' ' + amount)
        if response:
            txhash = response[0]
            return txhash
        disconnect(connect)

#restart specified servers
def reboot(servers = s['servers']):
    for server in servers:
        connect = ssh(server)
        if connect:
            send(connect, 'sudo reboot')
            send(connect, getpass())
            disconnect(connect)
    sleep(60)
    for server in servers:
        connect = ssh(server)
        if connect:
            send(connect, 'dapscoind')

#transfer and install binary files from local machine to all specified servers
def installBinToServers(pathtobin, servers=s['servers']):
    success = []
    for server in servers:
        success.append(installbinaries(server, pathtobin))
    return all(success)

#transfer and install binary files from local machine to specified server
def installbinaries(server, pathtobin):
    sendFile(server, pathtobin+'dapscoind.bin '+pathtobin+'dapscoincli.bin', '/usr/bin/')
    connect = ssh(server)
    if connect:
        send(connect, 'cd /usr/bin/')
        send(connect, 'rm dapscoind dapscoin-cli')
        send(connect, 'mv dapscoind.bin dapscoind')
        send(connect, 'mv dapscoin-cli.bin dapscoin-cli')
        disconnect(connect)
        return 1
    else:
        return 0

# def transfer(masternode, worker, amount=s['coinamount'] ):
#     connect = ssh(masternode)
#     send(connect, 'dapscoind')#needs to connect
#     send(connect, 'dapscoin-cli '+s['serveroption']+'masternode genkey')
#     coinAddress = send(connect,'dapscoin-cli '+s['serveroption']+'getaccountaddress'+s['alias'])#what is alias?
#     print coinAddress
#     disconnect(connect)
#     connect = ssh(worker)
#     send(connect, 'dapscoin-cli '+s['serveroption']+'sendtoaddress '+coinAddress+amount)
#     disconnect(connect)
#     connect = ssh(masternode)
#     send(connect, 'dapscoin-cli '+s['serveroption']+'getbalance')


def awaitWorkers(workers, amount=s['coinamount']):
    ready = False
    while (not ready):
        ready = True
        for worker in workers:
            connect = ssh(worker)
            balance = send(connect, 'dapscoin-cli '+s['serveroption']+'getbalance')
            if (balance<amount):
                ready = False
            disconnect(connect)
        sleep(s['checkworkerinterval'])

#use glcoud to automatically generate key, set permissions and open ssh shell to specified servers
def autoGCloud(servers=s['servers']):
    for server in servers:
        call('xterm -e gcloud compute --project "'+s['project']+'" ssh --zone "'+s['zone']+'" "'+server['name']+'"', shell=True)


#-------------------------------------------------
def runArgs():
    if (len(args)):
        for arg in args:
            if (arg['k'].find('stat')!=-1):
                if (len(arg['v'])):
                    status(arg['v'])
                else:
                    status()
            if (arg['k'].find('auto')!=-1):
                if (len(arg['v'])):
                    autoGCloud(arg['v'])
                else:
                    autoGCloud()
            if (arg['k'].find('transfer')!=-1):
                if (len(arg['alt'])>1):
                    transferFromMainWallet(arg['alt'][0], arg['alt'][1])
                else:
                    transferFromMainWallet(arg['alt'][0])
            if (arg['k'].find('restartwallet')!=-1):
                restartAllWallets(arg['hard'])
            if (arg['k'].find('stopdaemon')!=-1):
                if (len(arg['v'])):
                    stopAllWalletDaemons(arg['v'])
                else:
                    stopAllWalletDaemons()
            if (arg['k'].find('start')!=-1):
                startStakingWallets(arg['v'], arg['hard'])
            if (arg['k'].find('genstakingconfig')!=-1):
                genStakingNodeConfigFileScript(arg['v'])
            if (arg['k'].find('inst')!=-1):
                if (len(arg['alt'])):
                    if (len(arg['v'])):
                        installBinToServers(arg['alt'][0],arg['v'])
                    else:
                        installBinToServers(arg['alt'][0])
                else:
                    print "Could not install binaries. Please provide a source path."

runArgs()
print args



#sendFile(s['main'], 'test.test', '/home/dapstest/')
#sendFile(s['main'], 'boot/', '/home/dapstest/','-r')
#genConfigFileScript(s['masternodes'][0],'92zcRZrsy2JJjuY9kXGA4n7jSihfjGzrjKwB4s4Mq4UG42NPgBe', '38.29.176.86')
#masternodeScript(s['masternodes'],s['stakingnodes'][0])
