
PoA miner 0.1                     "Based on ccminer"
---------------------------------------------------------------

***************************************************************

***************************************************************

>>> Introduction <<<

This is a CUDA accelerated mining application which handle :

DAPScoin

where some of these coins have a VERY NOTABLE nVidia advantage
over competing AMD (OpenCL Only) implementations.

We did not take a big effort on improving usability, so please set
your parameters carefuly.

THIS PROGRAMM IS PROVIDED "AS-IS", USE IT AT YOUR OWN RISK!

If you're interessted and read the source-code, please excuse
that the most of our comments are in german.

>>> Command Line Interface <<<

This code is based on the pooler cpuminer and inherits
its command line interface and options.

  -a, --algo=ALGO       specify the algorithm to use
                          scrypt      use to mine Scrypt coins (Litecoin, Dogecoin, etc)

  -d, --devices         gives a comma separated list of CUDA device IDs
                        to operate on. Device IDs start counting from 0!
                        Alternatively give string names of your card like
                        gtx780ti or gt640#2 (matching 2nd gt640 in the PC).

  -i, --intensity=N[,N] GPU threads per call 8-25 (2^N + F, default: 0=auto)
                        Decimals and multiple values are allowed for fine tuning
      --cuda-schedule   Set device threads scheduling mode (default: auto)
  -f, --diff-factor     Divide difficulty by this factor (default 1.0)
  -m, --diff-multiplier Multiply difficulty by this value (default 1.0)
  -o, --url=URL         URL of mining server
  -O, --userpass=U:P    username:password pair for mining server
  -u, --user=USERNAME   username for mining server
  -p, --pass=PASSWORD   password for mining server
      --cert=FILE       certificate for mining server using SSL
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy
  -t, --threads=N       number of miner threads (default: number of nVidia GPUs in your system)
  -r, --retries=N       number of times to retry if a network call fails
                          (default: retry indefinitely)
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 15)
      --shares-limit    maximum shares to mine before exiting the program.
      --time-limit      maximum time [s] to mine before exiting the program.
  -T, --timeout=N       network timeout, in seconds (default: 300)
  -s, --scantime=N      upper bound on time spent scanning current work when
                        long polling is unavailable, in seconds (default: 5)
      --submit-stale    ignore stale job checks, may create more rejected shares
  -n, --ndevs           list cuda devices
  -N, --statsavg        number of samples used to display hashrate (default: 30)
      --no-gbt          disable getblocktemplate support (height check in solo)
      --no-longpoll     disable X-Long-Polling support
      --no-stratum      disable X-Stratum support
  -q, --quiet           disable per-thread hashmeter output
      --no-color        disable colored output
  -D, --debug           enable debug output
  -P, --protocol-dump   verbose dump of protocol-level activities
  -b, --api-bind=port   IP:port for the miner API (default: 127.0.0.1:4068), 0 disabled
      --api-remote      Allow remote control, like pool switching, imply --api-allow=0/0
      --api-allow=...   IP/mask of the allowed api client(s), 0/0 for all
      --max-temp=N      Only mine if gpu temp is less than specified value
      --max-rate=N[KMG] Only mine if net hashrate is less than specified value
      --max-diff=N      Only mine if net difficulty is less than specified value
      --max-log-rate    Interval to reduce per gpu hashrate logs (default: 3)
      --pstate=0        will force the Geforce 9xx to run in P0 P-State
      --plimit=150W     set the gpu power limit, allow multiple values for N cards
                          on windows this parameter use percentages (like OC tools)
      --tlimit=85       Set the gpu thermal limit (windows only)
      --keep-clocks     prevent reset clocks and/or power limit on exit
      --hide-diff       Hide submitted shares diff and net difficulty
  -B, --background      run the miner in the background
      --benchmark       run in offline benchmark mode
      --cputest         debug hashes from cpu algorithms
      --cpu-affinity    set process affinity to specific cpu core(s) mask
      --cpu-priority    set process priority (default: 0 idle, 2 normal to 5 highest)
  -c, --config=FILE     load a JSON-format configuration file
                        can be from an url with the http:// prefix
  -V, --version         display version information and exit
  -h, --help            display this help text and exit


Scrypt specific options:
  -l, --launch-config   gives the launch configuration for each kernel
                        in a comma separated list, one per device.
      --interactive     comma separated list of flags (0/1) specifying
                        which of the CUDA device you need to run at inter-
                        active frame rates (because it drives a display).
  -L, --lookup-gap      Divides the per-hash memory requirement by this factor
                        by storing only every N'th value in the scratchpad.
                        Default is 1.
      --texture-cache   comma separated list of flags (0/1/2) specifying
                        which of the CUDA devices shall use the texture
                        cache for mining. Kepler devices may profit.
      --no-autotune     disable auto-tuning of kernel launch parameters

CryptoNight specific options:
  -l, --launch-config   gives the launch configuration for each kernel
                        in a comma separated list, one per device.
      --bfactor=[0-12]  Run Cryptonight core kernel in smaller pieces,
                        From 0 (ui freeze) to 12 (smooth), win default is 11
                        This is a per-device setting like the launch config.

Wildkeccak specific:
  -l, --launch-config   gives the launch configuration for each kernel
                        in a comma separated list, one per device.
  -k, --scratchpad url  Url used to download the scratchpad cache.


>>> Examples <<<


Example for scryptcoin Mining on scryptcoinpool.com with a single gpu in your system
    poaminer -t 1 -a scrypt -o stratum+tcp://stratum01.dapscoinpool.com:5333 -u <<username.worker>> -p <<workerpassword>> -v 8


Example for scryptcoin Mining on hvc.1gh.com with a dual gpu in your system
    poaminer -t 2 -a scrypt -o stratum+tcp://dapspool.com:5333/ -u <<WALLET>> -p x -v 8


Example for Fuguecoin solo-mining with 4 gpu's in your system and a Fuguecoin-wallet running on localhost
    poaminer -q -s 1 -t 4 -a scrypt -o http://localhost:53572/ -u <<myusername>> -p <<mypassword>>


Example for Fuguecoin pool mining on dapspool.com with all your GPUs
    poaminer -q -a fugue256 -o stratum+tcp://dapspool.com:3340/ -u YOURWALLETADDRESS.1 -p YOUREMAILADDRESS



For solo-mining you typically use -o http://127.0.0.1:xxxx where xxxx represents
the rpcport number specified in your wallet's .conf file and you have to pass the same username
and password with -O (or -u -p) as specified in the wallet config.

The wallet must also be started with the -server option and/or with the server=1 flag in the .conf file

>>> Configuration files <<<

With the -c parameter you can use a json config file to set your prefered settings.
An example is present in source tree, and is also the default one when no command line parameters are given.
This allow you to run the miner without batch/script.


>>> API and Monitoring <<<

With the -b parameter you can open your poaminer to your network, use -b 0.0.0.0:4068 if required.
On windows, setting 0.0.0.0 will ask firewall permissions on the first launch. Its normal.

Default API feature is only enabled for localhost queries by default, on port 4068.

You can test this api on linux with "telnet <miner-ip> 4068" and type "help" to list the commands.
Default api format is delimited text. If required a php json wrapper is present in api/ folder.

I plan to add a json format later, if requests are formatted in json too..


>>> Additional Notes <<<

This code should be running on nVidia GPUs ranging from compute capability
3.0 up to compute capability 5.2. Support for Compute 2.0 has been dropped
so we can more efficiently implement new algorithms using the latest hardware
features.

