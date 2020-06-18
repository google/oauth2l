import React from "react";
import Enzyme, { mount } from "enzyme";
import Adapter from "enzyme-adapter-react-16";

import Credentials from "../components/Credentials";

Enzyme.configure({ adapter: new Adapter() });

// test applications use-cases form user's pov. Users access information on a web page and interact with available controls
// assert pm react dom state
// shawllow rendering is not used for this as we need to be able to test the child components

describe("Credential Component", () => {
  let wrapper;

  beforeEach(() => {
    wrapper = mount(<Credentials />);
  });

  it("renders the page", () => {
    expect(wrapper).toBeDefined();
  });
});
