
const settings = require('Config/settings')
const hostUrl=`http://${settings.address}${settings.port}/api/`

const Actions = {
    "getBlockDetailData": {
        "header": { "BLOCK HEIGHT": async () => { return "123456" } },
        "CURRENT SUPPLY": async () => { return "50,000,000.000 DAPS" },
        "HASHRATE": async () => { return "000.000 MH/S" },
        "DIFFICULTY": async () => { return "1234.5 K" },
        "NETWORK STATUS": async () => { return "GOOD" }
    },
    "getPosBlocksData": () => {
        return {
            "headers": ["HEIGHT", "AGE", "HASH", "SIZE"],
            "0": ["100 541", "1 minute ago", "ecf2b2633cc6122fb24404675894943934958", "5 kb"],
            "1": ["100 540", "2 minutes ago", "ecf2b2633cc6122fb24404675894943934958", "10 kb"],
            "2": ["100 541", "3 minute ago", "ecf2b2633cc6122fb24404675894943934958", "51 kb"],
            "3": ["100 541", "5 minute ago", "ecf2b2633cc6122fb24404675894943934958", "15 kb"],
            "4": ["100 541", "6 minute ago", "ecf2b2633cc6122fb24404675894943934958", "35 kb"],
            "5": ["100 541", "9 minute ago", "ecf2b2633cc6122fb24404675894943934958", "52 kb"],
            "6": ["100 541", "10 minute ago", "ecf2b2633cc6122fb24404675894943934958", "15 kb"],
            "7": ["100 541", "32 minute ago", "ecf2b2633cc6122fb24404675894943934958", "59 kb"],
            "8": ["100 541", "45 minute ago", "ecf2b2633cc6122fb24404675894943934958", "5 kb"],
            "9": ["100 541", "65 minute ago", "ecf2b2633cc6122fb24404675894943934958", "45 kb"],
        }
    },
    "getPoaBlocksData": () => {
        return {
            "headers": ["HEIGHT", "AGE", "HASH", "SIZE"],
            "0": ["100 541", "1 minute ago", "ecf2b2633cc6122fb24404675894943934958", "5 kb"],
            "1": ["100 540", "2 minutes ago", "ecf2b2633cc6122fb24404675894943934958", "10 kb"],
            "2": ["100 541", "3 minute ago", "ecf2b2633cc6122fb24404675894943934958", "51 kb"],
            "3": ["100 541", "5 minute ago", "ecf2b2633cc6122fb24404675894943934958", "15 kb"],
            "4": ["100 541", "6 minute ago", "ecf2b2633cc6122fb24404675894943934958", "35 kb"],
            "5": ["100 541", "9 minute ago", "ecf2b2633cc6122fb24404675894943934958", "52 kb"],
            "6": ["100 541", "10 minute ago", "ecf2b2633cc6122fb24404675894943934958", "15 kb"],
            "7": ["100 541", "32 minute ago", "ecf2b2633cc6122fb24404675894943934958", "59 kb"],
            "8": ["100 541", "45 minute ago", "ecf2b2633cc6122fb24404675894943934958", "5 kb"],
            "9": ["100 541", "65 minute ago", "ecf2b2633cc6122fb24404675894943934958", "45 kb"],
        }
    },
    "getTxsData": () => {
        return {
            "headers": ["HEIGHT", "AGE", "SIZE", "RING SIZE", "TRANSACTION HASH", "AMOUNT"],
            "0": ["100 541", "1 minute ago", "5 kb", "5", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
            "1": ["100 541", "1 minute ago", "5 kb", "4", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
            "2": ["100 541", "1 minute ago", "5 kb", "8", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
            "3": ["100 541", "1 minute ago", "5 kb", "6", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
            "4": ["100 541", "1 minute ago", "5 kb", "3", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
            "5": ["100 541", "1 minute ago", "5 kb", "9", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
            "6": ["100 541", "1 minute ago", "5 kb", "7", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
            "7": ["100 541", "1 minute ago", "5 kb", "6", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
            "8": ["100 541", "1 minute ago", "5 kb", "9", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
            "9": ["100 541", "1 minute ago", "5 kb", "11", "ecf2b2633cc6122fb24404675894943934958", "Hidden"],
        }
    },
    "getBlockDetail": () => {
        return {
            "type": "PoS",
            "detailData": {
                "03/26/2018": "07:34:12",
                "AUDIT OF DAPS SUPLLY": "AS EXPECTED",
                "BLOCK REWARD EARNED": "6000 DAPS",
                "DIFFICULTY": "1234.5"
            },
            "blockData": {
                "headers": ["HEIGHT", "AGE", "HASH", "SIZE"],
                "0": ["100 541", "1 minute ago", "5 kb", "5"]
            },
            "txList": {
                "headers": ["POS BLOCK HASH", "HEIGHT", "AGE"],
                "0": ["345hbj3b4hj5b3hjb45jh3b45jhb3hj45b3hj", "100541", "1 minute ago"],
                "1": ["345hbj3b4hj5b3hjb45jh3b45jhb3hj45b3hj", "345432", "3 minutes ago"],
                "2": ["345hbfntrhjtrdtndhnrrdnrnrthndj45b3hj", "348973", "5 minutes ago"],
                "3": ["34545645645645nxdhfgn76nfg786ngf5b3hj", "348975", "10 minutes ago"],
                "4": ["nwlentjwekhjkh43j5j345jl345jkl345nknk", "435385", "15 minutes ago"],
            },
            "PosMessage": "ON THIS DATE AND TIME, THE DAPS CHAIN'S CURRENT SUPPLY WAS AUDITED",
            "Audited": { " POS BLOCKS AUDITED": "60" },
        }
    },
    // "getBlockDetail": () => {
    //     return {
    //         "type":"PoA",
    //         "detailData":{
    //             "03/26/2018":"07:34:12",
    //             "TOKENS GENERATED": "1050",
    //             "DIFFICULTY":"1234.5"
    //         },
    //         "blockData":{
    //             "headers": ["HEIGHT", "AGE", "HASH", "SIZE"],
    //             "0": ["100 541", "1 minute ago", "5 kb", "5"]
    //         },
    //         "txList":{
    //             "headers": ["TRANSACTION HASH", "SIZE", "FEE PER KB"],
    //             "0": ["345hbj3b4hj5b3hjb45jh3b45jhb3hj45b3hj", "6kb", "0.0000 DAPS"],
    //             "1": ["345hbj3b4hj5b3hjb45jh3b45jhb3hj45b3hj", "6kb", "0.0000 DAPS"],
    //             "2": ["345hbfntrhjtrdtndhnrrdnrnrthndj45b3hj", "6kb", "0.0000 DAPS"],
    //             "3": ["34545645645645nxdhfgn76nfg786ngf5b3hj", "6kb", "0.0000 DAPS"],
    //             "4": ["nwlentjwekhjkh43j5j345jl345jkl345nknk", "6kb", "0.0000 DAPS"],
    //         },
    //          "poaStatus":"EXTRACTED MASTERNODE / STAKING"
    //     }
    // },
    "getTxDetail": (id) => {
        return {
            "detailData": {
                "03/26/2018": "07:34:12",
                "Confirmations": "5 of 10"
            },
            "txData": {
                "headers": ["HEIGHT", "AGE", "SIZE", "RING SIZE", "TRANSACTION HASH", "FEE"],
                "0": ["100 541", "1 minute ago", "5 kb", "5", "ecf2b2633cc6122fb24404675894943934958", "5.0000 DAPS"]
            },
            "input": {
                "headers": ["Key Image", "Amount"],
                "0": ["345hbj3b4hj5b3hjb45jh3b45jhb3hj45b3hj", "hidden"],
                "1": ["jgwneiognv34n4l3n6l345jlk235jk25nn6l3", "hidden"],
                "2": ["634789563nhjnk3n4jk5h345k3h5j3k4n534k", "hidden"],
            },
            "output": {
                "headers": ["Stealth Address", "Amount"],
                "0": ["345hbj3b4hj5b3hjb45jh3b45jhb3hj45b3hj", "hidden"],
                "1": ["jgwneiognv34n4l3n6l345jlk235jk25nn6l3", "hidden"],
            },
        }
    },
    "getNetworkDetailData": {
        "header": { "SINCE LAST POA BLOCK": async () => { return "00:00:00" } },
        "TOTAL NODES": async () => { return "45 987" },
        "TOTAL ACTIVE MASTERNODES": async () => { return "3456" },
        "BITCOIN PRICE": async () => { return "5528.33 USD" },
        "BTC / DAPS": async () => { return "0.000123 DAPS" }
    }
}

export default Actions;