/* eslint "require-jsdoc": ["error", {
    "require": {
        "FunctionDeclaration": true,
        "MethodDefinition": true,
        "ClassDeclaration": false
    }
}]*/

import React, { Fragment } from "react";
import { MDBBtn } from "mdbreact";
import PropTypes from "prop-types";

/**
 * @param {string} props holds the name of the button
 * @return {Fragment} returns a button with names
 */
function Button(props) {
  return (
    <Fragment>
      <MDBBtn color="primary">{props.name}</MDBBtn>
    </Fragment>
  );
}
export default Button;

Button.propTypes = {
  name: PropTypes.string,
};
