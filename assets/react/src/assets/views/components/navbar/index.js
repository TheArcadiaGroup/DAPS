import React from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'
import { Link } from 'react-router-dom';

const NavBar = (props) => {
    return (<div className={"NavBar " + Style.NavBar}>
        <div id="logo" className={"Logo " + Style.Logo}>
            <div id="dapsLogo" />
            <h1 id="dapsName"><a href="/">DAPS EXPLORER</a></h1>
        </div>
        <div id="ink" className={"Link " + Style.Link}>
            <Link to={`/explorer/blocks/?limit=${props.pagesize}&page=0`} id="allLink">All Blocks</Link>
            <Link to={`../Posblocks/?limit=${props.pagesize}&page=0`} id="posLink">PoS Blocks</Link>
            <Link to={`../Poablocks/?limit=${props.pagesize}&page=0`} id="poalink">PoA Blocks</Link>
            <Link to={`/explorer/transactions/?limit=${props.pagesize}&page=0`} id="txLink">Transactions</Link>
        </div>
    </div>
    )
};

//NavBar.proptypes = {  }

export default NavBar;