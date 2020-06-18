import React from "react";
import Enzyme, { mount } from "enzyme";
import Adapter from "enzyme-adapter-react-16";

import App from "./App";

Enzyme.configure({ adapter: new Adapter() });

describe("Credential Component", () => {
  let wrapper;

  beforeEach(() => {
    wrapper = mount(<App />);
  });

  it("renders the page", () => {
    expect(wrapper).toBeDefined();
  });
});
