/* eslint "require-jsdoc": ["error", {
    "require": {
        "FunctionDeclaration": true,
        "MethodDefinition": true,
        "ClassDeclaration": false
    }
}]*/

import React from "react";
import PropTypes from "prop-types";

/**
 * It returns test + 10
 * @param {string} props - gives token type and format
 * @return {div} returns div for now, will change later
 */
export default function Scopes(props) {
  return (
    <div>
      <h1>Message received</h1>
      <h1>{props.type} </h1>
      <h1>{props.form}</h1>
    </div>
  );
}

Scopes.propTypes = {
  type: PropTypes.string,
  form: PropTypes.string,
};
