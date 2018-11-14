
PoA miner 0.1                     "Based on ccminer"
---------------------------------------------------------------

***************************************************************

***************************************************************

>>> Introduction <<<

This is a CUDA accelerated mining application which handle :

Decred (Blake256 14-rounds - 180 bytes)
HeavyCoin & MjollnirCoin
FugueCoin
GroestlCoin & Myriad-Groestl
Lbry Credits
JackpotCoin (JHA)
QuarkCoin family & AnimeCoin
TalkCoin
DarkCoin and other X11 coins
Chaincoin and Flaxscript (C11)
Saffroncoin blake (256 14-rounds)
BlakeCoin (256 8-rounds)
Qubit (Digibyte, ...)
Luffa (Joincoin)
Keccak (Maxcoin)
Pentablake (Blake 512 x5)
1Coin Triple S
Neoscrypt (FeatherCoin)
x11evo (Revolver)
phi2 (LUXCoin)
Scrypt and Scrypt:N
Scrypt-Jane (Chacha)
sib (Sibcoin)
Skein (Skein + SHA)
Signatum (Skein cubehash fugue Streebog)
SonoA (Sono)
Tribus (JH, keccak, simd)
Woodcoin (Double Skein)
Vanilla (Blake256 8-rounds - double sha256)
Vertcoin Lyra2RE
Ziftrcoin (ZR5)
Boolberry (Wild Keccak)
Monero (Cryptonight v7 with -a monero)
Aeon (Cryptonight-lite)

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
                          allium      use to mine Garlic
                          bastion     use to mine Joincoin
                          bitcore     use to mine Bitcore's Timetravel10
                          blake       use to mine Saffroncoin (Blake256)
                          blakecoin   use to mine Old Blake 256
                          blake2s     use to mine Nevacoin (Blake2-S 256)
                          bmw         use to mine Midnight
                          cryptolight use to mine AEON cryptonight variant 1 (MEM/2)
                          cryptonight use to mine original cryptonight
                          c11/flax    use to mine Chaincoin and Flax
                          decred      use to mine Decred 180 bytes Blake256-14
                          deep        use to mine Deepcoin
                          dmd-gr      use to mine Diamond-Groestl
                          equihash    use to mine ZEC, HUSH and KMD
                          fresh       use to mine Freshcoin
                          fugue256    use to mine Fuguecoin
                          groestl     use to mine Groestlcoin
                          hsr         use to mine Hshare
                          jackpot     use to mine Sweepcoin
                          keccak      use to mine Maxcoin
                          keccakc     use to mine CreativeCoin
                          lbry        use to mine LBRY Credits
                          luffa       use to mine Joincoin
                          lyra2       use to mine CryptoCoin
                          lyra2v2     use to mine Vertcoin
                          lyra2z      use to mine Zerocoin (XZC)
                          monero      use to mine Monero (XMR)
                          myr-gr      use to mine Myriad-Groest
                          neoscrypt   use to mine FeatherCoin, Trezarcoin, Orbitcoin, etc
                          nist5       use to mine TalkCoin
                          penta       use to mine Joincoin / Pentablake
                          phi1612     use to mine Seraph
                          phi2        use to mine LUXCoin
                          polytimos   use to mine Polytimos
                          quark       use to mine Quarkcoin
                          qubit       use to mine Qubit
                          scrypt      use to mine Scrypt coins (Litecoin, Dogecoin, etc)
                          scrypt:N    use to mine Scrypt-N (:10 for 2048 iterations)
                          scrypt-jane use to mine Chacha coins like Cache and Ultracoin
                          s3          use to mine 1coin (ONE)
                          sha256t     use to mine OneCoin (OC)
                          sia         use to mine SIA
                          sib         use to mine Sibcoin
                          skein       use to mine Skeincoin
                          skein2      use to mine Woodcoin
                          skunk       use to mine Signatum
                          sonoa       use to mine Sono
                          stellite    use to mine Stellite (a cryptonight variant)
                          timetravel  use to mine MachineCoin
                          tribus      use to mine Denarius
                          x11evo      use to mine Revolver
                          x11         use to mine DarkCoin
                          x12         use to mine GalaxyCash
                          x13         use to mine X13
                          x14         use to mine X14
                          x15         use to mine Halcyon
                          x16r        use to mine Raven
                          x16s        use to mine Pigeon and Eden
                          x17         use to mine X17
                          vanilla     use to mine Vanilla (Blake256)
                          veltor      use to mine VeltorCoin
                          whirlpool   use to mine Joincoin
                          wildkeccak  use to mine Boolberry (Stratum only)
                          zr5         use to mine ZiftrCoin

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


Example for Heavycoin Mining on heavycoinpool.com with a single gpu in your system
    poaminer -t 1 -a heavy -o stratum+tcp://stratum01.heavycoinpool.com:5333 -u <<username.worker>> -p <<workerpassword>> -v 8


Example for Heavycoin Mining on hvc.1gh.com with a dual gpu in your system
    poaminer -t 2 -a heavy -o stratum+tcp://hvcpool.1gh.com:5333/ -u <<WALLET>> -p x -v 8


Example for Fuguecoin solo-mining with 4 gpu's in your system and a Fuguecoin-wallet running on localhost
    poaminer -q -s 1 -t 4 -a fugue256 -o http://localhost:9089/ -u <<myusername>> -p <<mypassword>>


Example for Fuguecoin pool mining on dwarfpool.com with all your GPUs
    poaminer -q -a fugue256 -o stratum+tcp://erebor.dwarfpool.com:3340/ -u YOURWALLETADDRESS.1 -p YOUREMAILADDRESS


Example for Groestlcoin solo mining
    poaminer -q -s 1 -a groestl -o http://127.0.0.1:1441/ -u USERNAME -p PASSWORD

Example for Boolberry
    poaminer -a wildkeccak -o stratum+tcp://bbr.suprnova.cc:7777 -u tpruvot.donate -p x -k http://bbr.suprnova.cc/scratchpad.bin -l 64x360

Example for Scrypt-N (2048) on Nicehash
    poaminer -a scrypt:10 -o stratum+tcp://stratum.nicehash.com:3335 -u 3EujYFcoBzWvpUEvbe3obEG95mBuU88QBD -p x

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

