DAPS Core Daemon Management
=====================================

The strucutre and approach has changed to handle the daemon kick off, exewcution, status (inquire), restart and stop.  The sole bash script is no longer deploy.sh.  Currently, the inspect.sh is repsonsible for the following commands:

   1. Start : Start daemon, if dapscoind is already started script is aborts an displays 
   2. Restart : Restart daemon : restart if running, we kill it, wait, restart it, wait and report the PID! If not running we start it
   3. Stop : Stop the daemon
   4. Status : status pull the PID and launch daspcoin-cli getinfo (responds its repsonsive) if not, then not responsive flag the issue
   
   
~~The files of focus at this point are listed below:~~
 
   * ~~trycatch.sh helper file to mimic a normal try catch block~~ 
   * ~~prooftest.sh is a demonstration and proof~~ 
   * ~~deply.sh is the end target deployment script for daemon excution and manage~~ 

DAPS is a cutting edge cryptocurrency, with many features not available in most other cryptocurrencies.
- Anonymized transactions using coin mixing technology, we call it _Obfuscation_.
- Fast transactions featuring guaranteed zero confirmation transactions, we call it _SwiftTX_.
- Decentralized blockchain voting providing for consensus based advancement of the current Masternode
  technology used to secure the network and provide the above features, each Masternode is secured
  with a collateral of 10K DAPS.

More information at [dapscoin.org](http://www.dapscoin.org) Visit our ANN thread at [BitcoinTalk](http://www.bitcointalk.org/index.php?topic=1262920)

### DAPScoint scripts
<table>
<tr><td>name</td><td>descr</td></tr>
<tr><td>trycatch.sh</td><td>Implement a Try Catch helper script</td></tr>
 <tr><td>ddaps.sh</td><td>Main Script to manage worflow</td></tr> 
</table>

### BASH 
   * Bash version: *4.4.20(1)-release*
   
### PID Access
<table>
<tr><td>name</td><td>usage</td><td>returns</td></tr>
 <tr><td>pgrep</td><td>prgrep dapscoind</td><td>PID#</td></tr>
 <tr><td> </td><td> </td><td> </td></tr>
</table>

   
### dapscoin-cli
<table>
<tr><td>name</td><td>usage</td></tr>
<tr><td></td><td>Implement a Try Catch helper script</td></tr>
 <tr><td>ddaps.sh</td><td>Main Script to manage worflow</td></tr> 
</table>
