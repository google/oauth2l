/* eslint "require-jsdoc": ["error", {
    "require": {
        "FunctionDeclaration": true,
        "MethodDefinition": true,
        "ClassDeclaration": false
    }
}]*/

import React from "react";
import "./App.css";
import Credentials from "./components/Credentials";
import {
  MDBNavbar,
  MDBNavbarBrand,
  MDBContainer,
  MDBCol,
  MDBRow,
} from "mdbreact";
import { Route, NavLink, HashRouter } from "react-router-dom";
import Scopes from "./Scopes";
import Button from "./components/Button";

/**
 * @return {HashRouter} returns webapp as a whole
 */
function App() {
  return (
    <HashRouter>
      {" "}
      <div className="App">
        {" "}
        <MDBNavbar color="blue">
          {" "}
          <MDBNavbarBrand>
            {" "}
            <img
              src={"clogo.png"}
              width="250"
              alt="This is a logo for Google Cloud"
            />{" "}
          </MDBNavbarBrand>{" "}
        </MDBNavbar>{" "}
        <Route exact path="/" component={Credentials} />{" "}
        <Route path="/Scopes" component={Scopes} />{" "}
        <MDBContainer>
          {" "}
          <MDBRow>
            {" "}
            <MDBCol size="9"></MDBCol>{" "}
            <MDBCol>
              {" "}
              <div style={{ float: "right" }} className="next">
                {" "}
                <NavLink to="/Scopes">
                  <Button name="Next"> </Button>{" "}
                </NavLink>{" "}
              </div>{" "}
            </MDBCol>{" "}
          </MDBRow>{" "}
        </MDBContainer>{" "}
      </div>{" "}
    </HashRouter>
  );
}
export default App;
