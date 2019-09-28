import React from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'
import {Link} from 'react-router-dom'

import DataCircle from 'Components/datacircle'
import ListBox from 'Components/listbox'

import merge from 'deepmerge'

const Genesis = (props) => {

    let data = merge(props.data || {},{});
    let detailData = data.detailData || []; delete data.detailData;
    const blockData = data.blockData||{}; delete data.blockData;
    const type = data.type || "... Looking for"; delete data.type;

    return (<div id={props.id} className={"Genesis " + Style.Page}>
        <div id="GenesisTitle" className={`${Style.GenesisTitle}`}>
            <span className={`${Style.GenesisTitleContent1}`}>
                {detailData['DATE']}
            </span>
            <span className={`${Style.GenesisTitleContent2}`}>
                BLOCK ZERO
            </span>
            <span className={`${Style.GenesisTitleContent3}`}>
                {detailData['TIME']}
            </span>
        </div>
        <div id="GenesisDataHeader1" className={`${Style.GenesisDataHeader}`}>
            <div className={`${Style.GenesisDataHeaderBack1}`}>
                <span className={`${Style.GenesisDataHeader1}`}>
                    Height
                </span>
            </div>
            <div className={`${Style.GenesisDataHeaderBack2}`}>
                <span className={`${Style.GenesisDataHeader2}`}>
                    DAPS Supply
                </span>
            </div>
            <div className={`${Style.GenesisDataHeaderBack3}`}>
                <div className={`${Style.GenesisDataHeaderBack3_1}`}>
                    <span className={`${Style.GenesisDataHeader3}`}>
                        Type
                    </span>
                </div>
                <div className={`${Style.GenesisDataHeaderBack3_2}`}>
                </div>
            </div>
        </div>
        <div id="GenesisData1" className={`${Style.GenesisData}`}>
            <span className={`${Style.GenesisDataContent1}`}>
                {blockData['HEIGHT']}
            </span>
            <span className={`${Style.GenesisDataContent2}`}>
                {detailData['TOKENS GENERATED']} DAPS
            </span>
            <span className={`${Style.GenesisDataContent3}`}>
                {type}
            </span>
        </div>

        <div id="GenesisDataHeader2" className={`${Style.GenesisDataHeader}`}>
            <div className={`${Style.GenesisDataHeaderBack1}`}>
                <span className={`${Style.GenesisDataHeader1}`}>
                    Confirmations
                </span>
            </div>
            <div className={`${Style.GenesisDataHeaderBack2}`}>
                <span className={`${Style.GenesisDataHeader2}`}>
                    Difficulty
                </span>
            </div>
            <div className={`${Style.GenesisDataHeaderBack2_1}`}>
            </div>
        </div>
        <div id="GenesisData2" className={`${Style.GenesisData}`}>
            <span className={`${Style.GenesisDataContent1}`}>
                {blockData['CONFIRMATIONS']}
            </span>
            <span className={`${Style.GenesisDataContent2}`}>
                 {detailData['DIFFICULTY']} K
            </span>
        </div>

        <div id="GenesisDataHeader3" className={`${Style.GenesisDataHeader}`}>
            <div className={`${Style.GenesisDataHeaderBack1}`}>
                <span className={`${Style.GenesisDataHeader1}`}>
                    Hash
                </span>
            </div>
            <div className={`${Style.GenesisDataHeaderBack1_1}`}>
            </div>
        </div>
        <div id="GenesisData3" className={`${Style.GenesisData}`}>
            <span className={`${Style.GenesisDataContent1}`}>
                {blockData['HASH']}
            </span>
            <span className={`${Style.CopyBackground}`} onClick={() => { navigator.clipboard.writeText(blockData['HASH']) }}>
            </span>
        </div>
        
    </div>);
};

export default Genesis;