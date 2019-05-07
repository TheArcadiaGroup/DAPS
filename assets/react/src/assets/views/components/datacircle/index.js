import React from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'
import { renderToStaticMarkup } from 'react-dom/server'


const DataCircle = (props) => {
    const data = props.data || {};
    if (!data.header) data.header = "";
    if (!Array.isArray(data.item)) data.item = [data.item || '', 'Red']
    

    return (
        <div className={`DataCircle ${Style.ItemContainer} ${data.item[1]}`} style={props.style||{}}>
            <div className={"DataCircleHeader " + Style.DetailUpperHalf}>
                <h3 className={"Title Blue " + Style.Title}>{data.header}</h3>
            </div>
            <div className={"DataCircleItem " + Style.DetailLowerHalf}>
                {props.header?
                    <h2 className={`Blue ${Style.Data}`}>{data.item[0]}</h2>
                    :<h4 className={Style.Data}>{data.item[0]}</h4>}
            </div>
        </div>);
}

export default DataCircle;