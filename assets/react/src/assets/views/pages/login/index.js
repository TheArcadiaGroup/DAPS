import React from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'
import {Link, Redirect} from 'react-router-dom'
const settings = require('../../../../../config/settings')
const hostUrl = settings.endpoint || `http://${settings.address}${settings.port ? ':' + settings.port : ''}/`

const fakeAuth = {
  isAuthenticated: false,
  async authenticate(password, cb) {
    try {
      var response = await fetch(`${hostUrl}auth`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          pwd: password   
        })
      })
      const json = await response.json();
      if (json.status === 'ok') {
        this.isAuthenticated = true
        setTimeout(cb, 100);
      }
    } catch(err) {
      console.log(err);
    }
  }
}

export default fakeAuth;

class Login extends React.Component {
  state = {
    redirectToReferrer: false,
    Pwd: ''
  }
  
  login = () => {
    fakeAuth.authenticate(this.state.Pwd, () => {
      this.setState(() => ({
        redirectToReferrer: true
      }))
    })
  }

  onChangePwd = (e) => {
    this.setState({Pwd: e.target.value});
  }

  render() {
    const { from } = this.props.location.state || { from: { pathname: '/' } }
    const { redirectToReferrer } = this.state

    if (redirectToReferrer === true) {
      return <Redirect to={from} />
    }

    return (
      <div className={`Root ${Style.Root}`}>
        <h2 className={`title ${Style.Title}`}>You must log in to view the page</h2>
        <input type='password' className={`input ${Style.Pwd}`} onChange={this.onChangePwd} value={this.state.Pwd}></input>
        <button className={`button ${Style.Login}`} onClick={this.login}>Log in</button>
      </div>
    )
  }
}

export {Login, fakeAuth}