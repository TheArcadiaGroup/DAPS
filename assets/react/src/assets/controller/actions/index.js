
const settings = require('Config/settings')
let hostUrl = settings.endpoint || `http://${settings.address}${settings.port ? ':' + settings.port : ''}/`

// if (settings.endpoint) {
//     if (settings.port) {
//         hostUrl = hostUrl.substring(0, hostUrl.length - 1) + ':' + settings.port + '/';
//     }
// }

console.log(hostUrl + '\n');
console.log(settings.endpoint + '\n');
console.log(settings.address + '\n');
console.log(settings.port + '\n');

const toAgeStr = (date) => {
    let now = new Date(Date.now()),
        diff = Date.now() - date.getTime()
    let intervals = {
        years: diff / (365 * 24 * 60 * 60 * 1000),
        months: (now.getFullYear() - date.getFullYear()) * 12 - date.getMonth() + 1 + now.getMonth(),
        days: diff / (24 * 60 * 60 * 1000),
        hours: diff / (60 * 60 * 1000),
        minutes: diff / (60 * 1000),
        seconds: diff / (1000),
    }; Object.keys(intervals).forEach(interval => intervals[interval] = Math.floor(intervals[interval]))
    for (let interval in intervals)
        if (intervals[interval] > 1)
            return `${intervals[interval]} ${interval} ago`
    return 'error'
}

const Actions = {
    "getBlockDetailData": {
        "header": {
            "BLOCK HEIGHT": async () => {
                try {
                    return [await (await fetch(hostUrl + 'api/getblockcount')).json(), ""]
                } catch (err) {
                    try {
                        return [(await (await fetch(hostUrl + 'dapsapi/block/?limit=0&report=0')).json()).data.length, "Yellow"]
                    } catch (err) { console.error("hashrate", err); return [null, "Red"]; }
                }
            }
        },
        "SUPPLY": async () => {
            try {
                return [Math.ceil((await (await fetch(hostUrl + 'api/gettxoutsetinfo')).json()).total_amount), "Green"]
            } catch (err) { console.error("supply", err); return [null, "Red"] }
        },
        "HASHRATE": async () => {
            try {
                return [await (await fetch(hostUrl + 'api/getnetworkhashps')).json(), "Green"]
            } catch (err) { console.error("hashrate", err); return [null, "Red"]; }
        },
        "DIFFICULTY": async () => {
            try {
                return [await (await fetch(hostUrl + 'api/getdifficulty')).json(), "Green"]
            } catch (err) { console.error("difficulty", err); return [null, "Red"]; }
        },
        "NETWORK STATUS": async () => {
            try {
                return (await (await fetch(hostUrl + 'api/getconnectioncount')).json()) ?
                    ["GOOD", "Green"]
                    : ["CHAIN ERROR", "Red"]
            } catch (err) { console.error("netStat", err); return ["SERVER ERROR", "Red"]; }
        }
    },


    "getList": async (collection, query = null) => {
        let returnObj = {}
        try {
            let result = await (await fetch(hostUrl + `dapsapi/${collection}/${query ? `${query}` : ''}`)).json()

            if (result.data)
                switch (collection.toLowerCase()) {
                    case "block": returnObj = {
                        "ids": result.data.map((block, i) => block.hash),
                        "headers": ["HEIGHT", "AGE", "HASH", "SIZE"],
                        ...result.data.map((block, i) => [
                            `${block.height}`,
                            `${toAgeStr(new Date(block.time * 1000))}`,
                            `${block.hash}`,
                            `${block.size / 1000} kb`
                        ])
                    }; break
                    case "tx": returnObj = {
                        "ids": result.data.map((tx, i) => tx.txid),
                        "headers": ["HEIGHT", "AGE", "SIZE", "RING SIZE", "TRANSACTION HASH", "AMOUNT"],
                        ...result.data.map((tx, i) => [
                            `${tx.blockindex}`,
                            `${toAgeStr(new Date(tx.time * 1000))}`,
                            `${parseFloat(tx.blocksize) / 1000} kb`,
                            `${tx.ringsize}`,
                            `${tx.txid}`,
                            `${tx.value || 'hidden'}`,
                        ])
                    }; break
                };
        } catch (err) { console.error('getlist', err); return null }
        return returnObj
    },


    "getBlockDetail": async (blockhash) => {
        let returnObj = {}
        try {
            const receivedBlock = (typeof blockhash == 'object') ?
                blockhash :
                (await (await fetch(hostUrl + `dapsapi/block/?hash=${blockhash}&report=0`)).json()).data[0]
            const date = new Date(receivedBlock.time * 1000);
            returnObj = {
                "type": `${receivedBlock.minetype}`,
                "detailData": {
                    [`${date.toDateString()}`]: [date.toTimeString().match(/\d\d:\d\d:\d\d/g), "Yellow"],
                    "TOKENS GENERATED": [`${receivedBlock.moneysupply}`, "Yellow"],
                    "BLOCK REWARD EARNED": [`${receivedBlock.numaudited * 1050}`, "Yellow"],
                    "DIFFICULTY": [`${receivedBlock.difficulty}`, "Yellow"],
                },
                "blockData": {
                    "headers": ["HEIGHT", "AGE", "HASH", "SIZE"],
                    "0": [
                        `${receivedBlock.height}`,
                        `${toAgeStr(date)}`,
                        `${receivedBlock.hash}`,
                        `${parseFloat(receivedBlock.size) / 1000} kb`
                    ]
                },
                "txList": {
                    "headers": ["TRANSACTION HASH", "SIZE", "FEE PER KB"],
                    ...await Promise.all(receivedBlock.tx.map(async (txid, i) => {
                        let receivedTx = {}; try { receivedTx = (await (await fetch(hostUrl + `dapsapi/tx/?txid=${txid}&report=0`)).json()).data[0] } catch (err) { console.error(err) }
                        return [
                            receivedTx.txid || 'error',
                            (receivedTx.blocksize) ? `${receivedTx.blocksize / 1000} kb` : 'error',
                            receivedTx.txfee || 'error'
                        ]
                    }))
                },
                // "raw": receivedBlock,
                "poaStatus": /*(receivedBlock.minetype == 'PoS') ? "EXTRACTED MASTERNODE / STAKING" :*/ '',
                "PosMessage": (receivedBlock.minetype == 'PoA') ? "ON THIS DATE AND TIME, THE DAPS CHAIN'S CURRENT SUPPLY WAS AUDITED,[SPLIT]AND THE POS BLOCK REWARDS ADD UP TO THE EXPECTED AMOUNT." : '',
                "Audited": (receivedBlock.minetype == 'PoA') ? { " POS BLOCKS AUDITED": `${receivedBlock.numaudited}` } : ''
            }
        } catch (err) { console.error("block", error); return null }
        return await returnObj;
    },


    "getTxDetail": async (id) => {
        let returnObj = {}
        try {
            const receivedTx = (typeof id == 'object') ?
                id :
                (await (await fetch(hostUrl + `dapsapi/tx/?txid=${id}&report=0`)).json()).data[0];
            const date = new Date(receivedTx.time * 1000);
            const type = receivedTx.vout[0].scriptPubKey.type
            returnObj = {
                "detailData": {
                    [date.toDateString()]: [date.toTimeString().match(/\d\d:\d\d:\d\d/g), "Yellow"],
                    "Confirmations": [
                        `${receivedTx.confirmations} of ${receivedTx.confirmationsneeded}`,
                        (receivedTx.confirmations >= receivedTx.confirmationsneeded) ? "Green"
                            : (receivedTx.confirmations > 10) ? "Yellow" : "Red",
                    ],
                },
                "blockData": {
                    "headers": ["HEIGHT", "AGE", "SIZE", "RING SIZE", "TRANSACTION HASH", "FEE"],
                    "0": [
                        `${receivedTx.blockindex}`,
                        `${toAgeStr(date)}`,
                        `${parseFloat(receivedTx.blocksize) / 1000} kb`,
                        `${receivedTx.ringsize}`,
                        `${receivedTx.txid}`,
                        `${receivedTx.txfee}`
                    ]
                },
                "txPubkey" : receivedTx.txpubkey,
                "input": {
                    "headers": [receivedTx.vin.filter((vin) => vin.keyimage).length ? "Key Image" : ''],
                    ...receivedTx.vin.map((vin) => [`${vin.keyimage || ''}`])
                },
                "output": {
                    "headers": ["Stealth Address", "Amount"],
                    ...receivedTx.vout.map((vout, i) => [
                        `${(vout.scriptPubKey.type == 'pubkey') ?
                            vout.scriptPubKey.addresses[0] || 'error'
                            : vout.scriptPubKey.type}`,
                        `${vout.value ? vout.value : 'hidden'}`,
                    ])
                },
                "isStealth": (receivedTx.vout[0].scriptPubKey.type == 'pubkey') ? receivedTx.vout.map((vout, i) => (
                    vout.scriptPubKey.type == 'pubkey') ? {
                        "address": vout.scriptPubKey.addresses[0],
                        "encodedamount": vout.encoded_amount,
                        "encodedmask": vout.encoded_mask,
                        } : false) : false,
                // "raw": receivedTx,
            };
        } catch (err) { console.error("tx", err); return null; }
        return returnObj;
    },


    "getNetworkDetailData": {
        "header": {
            "LAST POA BLOCK": async () => {
                try {
                    let response = await (await fetch(hostUrl + 'dapsapi/block/?minetype=PoA&sort=-height&limit=1&report=0')).json()
                    let date = response.data ? new Date(response.data[0].time * 1000) : null
                    return date ? [toAgeStr(date), ""] : ['none found', "Yellow"]
                } catch (err) { console.error("lastpoa", err); return [null, "Red"]; }
            }
        },
        "NODES": async () => {
            try {
                return [(await (await fetch(hostUrl + 'api/getconnectioncount')).json()) || 'error', "Green"]
            } catch (err) { console.error("nodes", err); return [null, "Red"]; }
        },
        "MASTER NODES": async () => {
            try {
                let response = await (await fetch(hostUrl + 'api/getmasternodecount')).json()
                return [(response.total != undefined) ? response.total : 'disconnected', "Green"]
            } catch (err) { console.error("mnodes", err); return [null, "Red"]; }
        },
        // "BITCOIN PRICE": async () => {
        //     try {
        //         let response = await (await fetch(hostUrl + `dapsapi/stats/?coin=BTC&report=0`)).json()
        //         return [(response.data != undefined) ? `${response.data[0].last_price}` : 'not found', "Green"]
        //     } catch (err) { console.error("btcprice", err); return [null, "Red"]; }
        // },
        // "BTC / DAPS": async () => {
        //     try {
        //         let response = await (await fetch(hostUrl + `dapsapi/stats/?coin=${settings.coin}&report=0`)).json()
        //         return [(response.data != undefined) ? `${response.data[0].last_price}` : 'not found', "Green"]
        //     } catch (err) { console.error("btc/daps", err); return [null, "Red"]; }
        // }
    },


    "getBlockHash": async (index) => {
        try {
            let response = await fetch(hostUrl + `api/getblockhash?index` + index)
            return response
        } catch (err) { console.error("getblockhash", err); return null; }
    },

    "getSearchPromises": async (string) => {
        let returnObj = {}
        if (string.length > 1)
            returnObj = {
                tx: [
                    fetch(hostUrl + `dapsapi/tx/?txid=$regex:.*${string}.*`),
                ],
                block: [
                    fetch(hostUrl + `dapsapi/block/?hash=$regex:.*${string}.*`),
                    (!isNaN(string)) ?
                        fetch(hostUrl + `dapsapi/block/?height=${string}`)
                        : new Promise(resolve => resolve(true))
                ],
            }
        return returnObj
    },

    "getTxCount": async () => {
        try {
            let response = await (await fetch(hostUrl + `dapsapi/tx/?count=true`)).json()
            return response.data
        } catch (err) { console.error("txcount", err); return null; }
    },
    "getBlockCount": async () => {
        try {
            let response = await (await fetch(hostUrl + `dapsapi/block/?count=true`)).json()
            return response.data
        } catch (err) { console.error("blockcount", err); return null; }
    },
    "getPoaBlockCount": async () => {
        try {
            let response = await (await fetch(hostUrl + `dapsapi/block/?count=true&minetype='PoA'`)).json()
            return response.data
        } catch (err) { console.error("blockcount", err); return null; }
    },
    "getPosBlockCount": async () => {
        try {
            let response = await (await fetch(hostUrl + `dapsapi/block/?count=true&minetype='PoS'`)).json()
            return response.data
        } catch (err) { console.error("blockcount", err); return null; }
    }

}

export default Actions;