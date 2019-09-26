#launch dapscoind 
PID=0

checkstatus () {
     echo "Checking dapascoind status" 
     PID=$(pgrep dapscoind)
     if [ -z $PID ]
     then 
         return -1
     else 
         return $PID
     fi  
} 

getpid() {
  PID=$(pgrep dapscoind)
  return  $PID
}

messagesleep () {
  x=0;   
  echo -n "Waiting"
  while [ $x -lt $1 ]
  do
   echo -n "."
   sleep 1
   echo -n "."
   x=$[$x+1]
  done
  echo ""
}

start () {
     echo "Attempting dapscoind Start"
     PID=$(pgrep dapscoind)
     if ! [ -z $PID ]
     then 
       echo "dapscoind already started on PID='"$PID"'" 
       return $PID
     else 
       dapscoind --daemon 
       messagesleep 7
       checkstatus
       echo "dapscoind started on PID='"$PID"'"
       PID=$(pgrep dapscoind)
       return $PID
     fi 
} 

resync () {
     echo "Attempting dapscoind resync"
     PID=$(pgrep dapscoind)
     if ! [ -z $PID ]
     then 
       echo "dapscoind already started on PID='"$PID"'" 
       return $PID
     else 
       dapscoind -resync 
       messagesleep 7
       checkstatus
       echo "dapscoind resync issued and successful started on PID='"$PID"'"
       PID=$(pgrep dapscoind)
       return $PID
     fi 
} 

stop () {
    echo "Attempting dapscoind Stop"
    PID=$(pgrep dapscoind)
     if ! [ -z $PID ]
          then     
            echo "Stop dapscoind PID='"$PID"'" 
            echo "Stop Execution : gracefully"
            LastPID=$PID
            dapscoin-cli stop
            messagesleep 7
            checkstatus
            echo "dapscoind successfully stopped @PID='"$LastPID"'" 
          else
            echo "dapscoind is not executiing: "     
    fi
}

restart () {
    echo "Attempting dapscoind Restart"
    PID=$(pgrep dapscoind)
    if ! [ -z $PID ]
    then  
          LastPID = $PID
          stop 
          checkstatus
          if  [ -z $PID ]
          then     
             echo "dapscoind ending... PID='"@LastPID"'"      
          fi 
     fi 
     start
     checkstatus 
     return $PID
} 

case $1 in
     status) 
          checkstatus
          echo "Retrieving Status" $PID
          if ! [ -z $PID ]
          then     
            echo "Normal execution and responsive @PID='"$PID"'"
          else
            echo "dapscoind is not executing"     
          fi  
          ;;     
     restart) 
          echo "Restarting dapscoind"
          checkstatus
          LastPID=$PID
          if [ -z $PID ]
          then     
            echo echo "dapscoind not running"
            messagesleep 7
            start
            checkstatus 
          else
            echo "dapscoind is executing on process ID: " $PID
            echo "Stopping dapscoind @PID:"$PID
            stop
            checkstatus
            messagesleep 7
            echo "dapscoind @ PID:"$LastPID "Stopped"
            start
            checkstatus
            messagesleep 7
            echo "dapscoind is HALTED process ID: " $LastPID
            echo "dapscoind is executing on new process ID: " $PID
          fi  
          ;;
     start)
          echo "launch dapscoind: start"
          checkstatus
          if [ -z $PID ]
          then     
            start
            echo "dapscoind executing as PID:" $PID 
            messagesleep 7
          else
            echo "dapscoind is executing on process ID: " $PID
            echo "Start aborting - please try launchdaps.sh restart"     
          fi  
          ;; 
     stop)
          echo "Shutting down dapscoind: Stop"
          checkstatus        
          stop
          ;;
     getpid)
          getpid
          echo $PID    
          ;;        
     *)
          echo "Invalid input - '"$1"'"
          echo "Valid switches : start, stop, restart, status, resync"
          ;;
esac
 


