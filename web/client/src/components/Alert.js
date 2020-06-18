/* eslint "require-jsdoc": ["error", {
    "require": {
        "FunctionDeclaration": true,
        "MethodDefinition": true,
        "ClassDeclaration": false
    }
}]*/

import React from "react";
import { MDBContainer, MDBAlert } from "mdbreact";

/**
 * @return {MDBContainer} returns webapp as a whole
 */
function AlertP() {
  return (
    <MDBContainer>
      <MDBAlert color="warning">
        <strong>JWT</strong> type and a <strong> Header</strong> format cannot
        be chosen as a pair
      </MDBAlert>
    </MDBContainer>
  );
}

export default AlertP;
