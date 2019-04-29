import React from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'
import { Link } from 'react-router-dom'

import merge from 'deepmerge'

const ListBox = (props) => {
    let data = props.data || [[]];
    data = merge(props.data, {})
    let headers = data.headers || []; delete data.headers;
    let type = data.type || ''; delete data.type;
    let prim = data.prim || props.prim || ''; delete data.prim;

    if (!Array.isArray(data)) data = Object.values(data);  //flatten objects to arrays
    data = data.filter(item => (Array.isArray(item) && Array.isArray(item)))


    return (<div id={props.id+'Container' || Style.Table} className={props.className || "ListBoxContainer " + Style.Container} style={props.style||{}}>
        {props.title ? <h2>{props.title}</h2> : ''}
        {data.length ?
            <table id={props.id || 'ta'} className={"ListBox " + Style.Table}><tbody>
                <tr className={Style.Row}>
                    {headers.map((columnHeader, i) => <th key={i} id={`tableHeader${i}`} className={`TableHeader ${Style.Header}`}>{columnHeader}</th>)}
                </tr>
                {data.map((row, r) => {
                    return (<tr key={r}>
                        {row.map((item, c) => <td key={c} id={`tableItem${r}-${c}`} className={`TableItem ${Style.Item}`}>
                            {((typeof item != 'string') || (item.length != 64)) ?
                                item
                                : <div>
                                    <Link to={`../${prim}/${item}`}>{item}</Link>
                                    <div id={`copy${r}-${c}`} className={'CopyButton'}
                                        onClick={() => { navigator.clipboard.writeText(item) }}
                                    />
                                </div>}
                        </td>)}
                    </tr>)
                })}
            </tbody></table> : ''}
    </div>
    )
};

//ListBox.proptypes = {}

export default ListBox;