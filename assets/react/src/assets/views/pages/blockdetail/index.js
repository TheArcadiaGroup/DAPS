import React from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'
import {Link} from 'react-router-dom'

import DataCircle from 'Components/datacircle'
import ListBox from 'Components/listbox'

import merge from 'deepmerge'

const BlockDetail = (props) => {

    let data = merge(props.data || {},{});
    // detailData - object or array, creates DataCircles for all keys with key as header and value as item
    let detailData = data.detailData || []; delete data.detailData;
    if (!Array.isArray(detailData)) detailData = Object.entries(detailData);
    // blockData - object or array for BlockData ListBox
    const blockData = data.blockData||{}; delete data.blockData;
    // txList - object or array for blocklist ListBox
    const txList = data.txList||{}; delete data.txList;
    // type - block type (PoA PoS PoW)
    const type = data.type || "... Looking for"; delete data.type;

    

    let posMessage;
    if (data.PosMessage) {
        let PostMessages = data.PosMessage.split("[SPLIT]");
        posMessage = <div><h3>{PostMessages[0]}</h3><h3>{PostMessages[1]}</h3></div>
    } else
        postMessage = null;

    delete data.PosMessage;
    let audited = (data.Audited) ? Object.entries(data.Audited)[0] : null; delete data.Audited;
    if (audited) audited = <div><h1>{`${audited[1]}${audited[0]}`}</h1></div>
    const poaStatus = (data.poaStatus) ? <div><h4>{data.poaStatus}</h4></div> : null; delete data.poaStatus;

    return (<div id={props.id} className={"BlockDetail " + Style.Page}>
            <Link to={props.back? `../../${props.back}`:''}>Back</Link>
        <h2>{type} Block</h2>
        <ListBox id={`blockDataTable`} className={"ListBox " + Style.LargeListBox} data={blockData} prim='block'/>
        <div className={`BlockPanel ${Style.BlockPanel}`}>
            {detailData.map((dataItem, i) => <DataCircle data={{ header: dataItem[0], item: dataItem[1] }} />)}
        </div>
        <div>
            {poaStatus || ''}
            {posMessage || ''}
            {audited || ''}
        </div>
        <div>
            <ListBox id={`txListBox`} data={txList} prim='tx'/>
        </div>
    </div>);
};

export default BlockDetail;