DAEMON_FOLDER=/home/dapscoin/daemon/linux-poa-daemon
$DAEMON_FOLDER/dapscoin-cli stop
echo "Wait for 4 seconds"
sleep 4
echo "Now starting daemon and Wait for 10 seconds"
$DAEMON_FOLDER/dapscoind -daemon > $DAEMON_FOLDER/log.txt
sleep 10
echo "Checking block count"
$DAEMON_FOLDER/dapscoin-cli getblockcount
echo "Unlocking wallet"
$DAEMON_FOLDER/dapscoin-cli unlockwallet 1234567890 0
$DAEMON_FOLDER/dapscoin-cli getstakingstatus
echo "Finish restart"
