import React, { Component } from 'react'
import ListBox from 'Components/listbox'
import Style from './style.css'

import merge from 'deepmerge'

const ListPage = (props) => {
    let data = props.data ? merge(props.data, {}) : {}
    delete data.ids
    
    return (<div className={`ListPage ${Style.Page}`}>
        {props.title ? <h1>{props.title}</h1> : ''}
        {props.links}
        <ListBox data={data} />
    </div>)

}

//ListPage.proptypes = {  }

export default ListPage