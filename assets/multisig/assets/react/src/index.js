import BlockExplorer from "./app"
import React from "react"
import ReactDOM from "react-dom"
import {Login, fakeAuth} from 'Pages/login'
import { BrowserRouter, Route, Redirect, Switch } from 'react-router-dom';

const PrivateRoute = ({ component: Component, ...rest }) => (
  <Route {...rest} render={(props) => (
    fakeAuth.isAuthenticated === true
      ? <Component {...props} />
      : <Redirect to={{
          pathname: '/explorer/login',
          state: { from: props.location }
        }} />
  )} />
)

const Root = document.getElementById("root") 
Root? ReactDOM.render(<BrowserRouter>
                          <Switch>
							              <Route path="/explorer/login" exact component={Login}/>
                            <PrivateRoute path="/(\w+/|)(\w+/|)(.*|)" component={BlockExplorer}/>
                          </Switch>
                    </BrowserRouter>, Root) : false;
