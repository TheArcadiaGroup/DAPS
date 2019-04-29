import React, { Component } from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'

import DataCircle from 'Components/datacircle'

class StatusBar extends Component {
    constructor(props) {
        localStorage.clear()
        super(props);
        this.state = {
            data: {},
            header: {},
            getData: props.getData || {},
            getHeader: (props.getData) ? props.getData.header || {} : {},
            id: props.id || '',
        }
        this.lift = props.lift || ((state) => { })
        this.updateAll()
        setInterval(() => this.updateAll(),
            10000)
    }

    async get(label, func, type = 'data') {
        Object.assign(this.state[type], { [label]: await func() })
        this.setState({ [type]: { [label]: await func(), ...this.state[type] } }, this.lift(this.state))
    }

    updateAll = () => {
        Object.keys(this.state.getHeader).forEach((key) => { this.get(key, this.state.getHeader[key], 'header') })
        Object.keys(this.state.getData).forEach((key) => {
            (typeof this.state.getData[key] == 'function') ?
                this.get(key, this.state.getData[key], 'data') : ''
        })
    }

    render() {
        return (<div id={this.state.id} className={"StatusBar " + Style.Column}>
            
            {Object.entries(this.state.header)
                .map((item, i) =>
                    <DataCircle key={i} data={{ header: item[0], item: item[1] }} class={"StatusBarHeader " + Style.Header} header={true} />)}
            {Object.entries(this.state.data).sort((a, b) => {
                return b[0] > a[0]
            }).map((detailItem, i) =>
                <DataCircle key={i} data={{ header: detailItem[0], item: detailItem[1] }} class={"StatusBarItem " + Style.Item} />)}
        </div>);
    }
}

//StatusBar.proptypes = {  }

export default StatusBar;