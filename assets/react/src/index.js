import BlockExplorer from "./app"
import React from "react"
import ReactDOM from "react-dom"
import { BrowserRouter, Route } from 'react-router-dom';

const Root = document.getElementById("root") 
Root? ReactDOM.render(<BrowserRouter>
                            <Route path="/(\w+/|)(\w+/|)(.*|)" component={BlockExplorer}/>
                    </BrowserRouter>, Root) : false;
