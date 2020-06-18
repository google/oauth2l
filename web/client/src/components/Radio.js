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
 * @param {string} props holds information about the button
 * @return {div} returns Radio button that is used in Credentials page
 */
function Radio(props) {
  return (
    <div className="custom-control custom-radio">
      <input
        type="radio"
        name={props.name}
        value={props.value}
        className="custom-control-input"
        id={props.id}
        onChange={props.changed}
      />
      <label className="custom-control-label" htmlFor={props.id}>
        {props.value}
      </label>
    </div>
  );
}

export default Radio;

Radio.propTypes = {
  name: PropTypes.string,
  value: PropTypes.string,
  id: PropTypes.string,
  onChange: PropTypes.func,
  changed: PropTypes.bool,
};
