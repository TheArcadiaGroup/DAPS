import React, { Component } from "react";
import PropTypes from 'prop-types'
import Style from './style.css'
import {Link} from 'react-router-dom'
import merge from 'deepmerge'

import DataCircle from 'Components/datacircle'
import ListBox from 'Components/listbox'

const bs58 = require('bs58')
const cipher = require('secp256k1')
const sha256 = require('js-sha256').sha256;
const Int64BE = require("int64-buffer").Int64BE;
//   , sr = require('secure-random'); 

class TxDetail extends Component {
    constructor(props) {
        super(props);
        let data = merge({}, props.data || {});
        // detailData - object or array, creates DataCircles for all keys with key as header and value as item
        let detailData = data.detailData || [];
        if (!Array.isArray(detailData)) detailData = Object.entries(detailData);
        
        this.state = {
            id: props.id,
            back: props.back,
            data: data,
            detailData: detailData,
            blockData: data.blockData || [],
            input: data.input || [],
            output: data.output || [''],
        }
    }

    render() {
        var data = this.state.data;
        var detailData = this.state.detailData;
        var blockData = this.state.blockData;
        var input = this.state.input;

        return (<div id={this.state.id} className={"TxDetail " + Style.Page}>
        <Link to={this.state.back? `../../${this.state.back}`:''}>Back</Link>
        <ListBox id={`blockDataListBox`} className={"ListBox " + Style.LargeListBox} data={this.state.blockData} prim={data.prim}/>
        <div className={`TxPanel ${Style.TxPanel}`}>
            {detailData.map((dataItem, i) => <DataCircle data={{ header: dataItem[0], item: dataItem[1] }} style={{alignSelf:'center'}}/>) }
            {(data['isStealth']) ? <form id="revealForm" className={`RevealForm ${Style.Form}`}>
                <h3>??? DAPS</h3><br />
                <input id="address" type="text" placeholder="DAPS Address" /><br />
                <input id="viewkey" type="password" placeholder="Private Viewkey" /><br />
                <input type="submit" value="Reveal" onClick={(e)=>{
                    e.preventDefault()
                    // console.log(e)
                    // console.log('target',e.target)
                    // console.log('currenttarget',e.currentTarget)
                    // console.log('isStealth',data.isStealth)
                    let address = document.getElementById('address').value
                    let viewkey = document.getElementById('viewkey').value
                    let viewkey_bytes = bs58.decode(viewkey)
                    let txPub = data.txPubkey
                    txPub = txPub.match(/.{2}/g).reverse().join("")
                    
                    viewkey_bytes = viewkey_bytes.slice(1, viewkey_bytes.length - 5);

                    let txPub_bytes = Buffer.from(txPub, 'hex');
                    let sharedSec = cipher.publicKeyTweakMul(txPub_bytes, viewkey_bytes, true);
                    sharedSec = Buffer.from(sharedSec, 'hex');

                    let output = this.state.output;
                    console.log('output', output);
                    data.isStealth.forEach( (item, id) => {
                        if (item == false)
                            return;

                        let enc_mask = item.encodedmask;
                        let enc_amount = item.encodedamount;
                        enc_mask = Buffer.from(enc_mask, 'hex');
                        enc_amount = Buffer.from(enc_amount, 'hex');

                        let sharedSechash1 = sha256(Buffer.from(sha256(sharedSec), 'hex'));
                        sharedSechash1 = sharedSechash1.match(/.{2}/g).reverse().join("");
                        sharedSechash1 = Buffer.from(sharedSechash1, 'hex');

                        let sharedSechash2 = sha256(Buffer.from(sha256(sharedSechash1), 'hex'));
                        sharedSechash2 = sharedSechash2.match(/.{2}/g).reverse().join("");
                        sharedSechash2 = Buffer.from(sharedSechash2, 'hex');

                        let mask = Buffer.alloc(32);
                        let amount = Buffer.alloc(32);

                        amount.fill(0, 0, 8);
                        for (var i = 0; i < 32; i++) {
                            mask[i] = enc_mask[i] ^ sharedSechash1[i];
                            amount[i] = enc_amount[i % 8] ^ sharedSechash2[i];
                        }

                        let amountValue = new Int64BE(amount.slice(0, 8));
                        output[id][1] = (Number(amountValue) / 1000000000000).toFixed(2);
                    });
                    this.setState({output: output});
                }}/>
            </form> : ''}
        </div>
        <div className={`ioData ${Style.IO}`}>
            <ListBox id={`inputListBox`} className={"ListBox " + Style.SmallListBox} data={input} />
            <ListBox id={`outputListBox`} className={"ListBox " + Style.SmallListBox} data={this.state.output} />
        </div>
    </div>);
    }
}

export default TxDetail;