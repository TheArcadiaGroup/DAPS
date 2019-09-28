#!/bin/bash
export utilitiyException=100
export dapsCoinException=1200
source ./trycatch.sh

# start with a try
try
(   # open a subshell !!!
    echo "do a tree"
    [ tree ] && throw $AnException

    # echo "do dapscoin-ctl getblockcount"
    # dapscoin-ctl getblockcount || throw $AnotherException

    echo "finished"
)
# directly after closing the subshell you need to connect a group to the catch using ||
catch || {
    # now you can handle
    case $ex_code in
        $utilitiyException)
            echo "AUtilityException was thrown"
            echo $ex_code
        ;;
        $dapsCoinException)
            echo "AdapsCoinExceptionException was thrown"
            echo $ex_code
        ;;
        *)
            echo "An unexpected exception was thrown"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
            echo $ex_code
        ;;
    esac
}

echo $?
echo $$
echo "========"
