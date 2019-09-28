import React, { Component } from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'
import { Link, Router } from 'react-router-dom';
import { renderToStaticMarkup } from 'react-dom/server'

import Actions from 'Actions'

class SearchBar extends Component {
    constructor(props) {
        super(props)
        this.state = {
            string: '',
            lib: props.lib || new Map(),
            match: new Map(),
            links: new Map(),
            visible: false,
        }
    }

    makeLink(entry) {
        let isblock = (entry.minetype || entry.height)
        let type = isblock ? 'block' : 'tx'

        return <Link to={`/explorer/${type}/${isblock ? entry.hash : entry.txid}`}>
            {`${type.toUpperCase()}        ${
                isblock ?
                    `${entry.height} ${entry.minetype}`
                    : `${(entry.vout && entry.vout.length) ?
                        entry.vout[0].value : false || 'amount hidden'
                    } DAPS`
                }`}
            <br />
            {`${isblock ?
                entry.hash
                : entry.txid}`}
            <br />
        </Link>
    }

    async getData(string) {
        if (string.length) {
            let promises = await Actions.getSearchPromises(string)
            if (promises && promises.tx)
                promises.tx = promises.tx.map(pr => Promise.resolve(pr).then(async response => {
                    if (response.json) {
                        let match = await response.json()
                        if (match.data && match.data.length)
                            match.data.map(async tx => {
                                if (tx && tx.txid) {
                                    let formattedtx = await Actions.getTxDetail(tx)
                                    this.state.lib.set(tx.txid, formattedtx)
                                    this.state.match.set(tx.txid, tx)
                                    return formattedtx
                                }
                            })
                        return match
                    }
                }))

            if (promises && promises.block)
                promises.block.map(pr => Promise.resolve(pr).then(async response => {
                    if (response.json) {
                        let match = await response.json()
                        if (match.data && match.data.length)
                            match.data.map(async block => {
                                if (block && block.hash) {
                                    let formattedblock = await Actions.getBlockDetail(block)
                                    this.state.lib.set(block.hash, formattedblock)
                                    this.state.match.set(block.hash, block)
                                    return formattedblock
                                }
                            })
                        return match
                    }
                }))
            Promise.all(promises.tx || [].concat(promises.block || [])).then(() => this.filterResults())
        }
    }

    filterResults() {
        let newmatch = new Map()
        if (Array.from(this.state.match.keys()).length) {
            this.state.match.forEach((entry, id) => {
                if (
                    ((id.indexOf(this.state.string) != -1) ? true : false)
                    || (entry.height ? (`${entry.height}`.indexOf(this.state.string) != -1) : false)
                )
                    newmatch.set(id, entry)
            })
            this.state.match.clear()
            newmatch.forEach((v, k) =>
                this.state.match.set(k, v))
            this.state.match.forEach((entry, id) => {
                if (!this.state.links.has(id)) {
                    this.state.links.set(id, this.makeLink(entry))
                }
            })
            this.setState({})
        }
    }

    handleChange = (e) => {
        this.setState({ string: e.target.value },
            () => this.getData(this.state.string))
    }

    handleFocus = (e) => {
        const type = e.type
        setTimeout(() => {
            this.setState({ visible: (type != 'blur') })
        }, 250)
    }

    render() {
        let keys = Array.from(this.state.match.keys())

        return (
            <div id="SearchBox" className={"SearchBox " + Style.SearchBox}>
                <input type="text" id="searchBar" className={"SearchBar " + Style.SearchBar}
                    onChange={this.handleChange}
                    onFocus={this.handleFocus}
                    onBlur={this.handleFocus}
                />
                <div id="SearchIcon" />
                {(keys.length) ?
                    <div id="SearchResult" style={{ visibility: this.state.visible ? 'visible' : 'hidden' }}>
                        {Array.from(this.state.match.keys()).map(key =>
                            <div>{this.state.links.get(key)}<br /></div>)}
                    </div>
                    : ''}
            </div>
        )
    }
}

//SearchBar.proptypes = {  }

export default SearchBar;