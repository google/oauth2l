import React from "react";
import Radio from "../components/Radio";
import Enzyme, { shallow } from "enzyme";
import Adapter from "enzyme-adapter-react-16";

Enzyme.configure({ adapter: new Adapter() });

describe("Radio Component", () => {
  let wrapper;
  beforeEach(() => {
    wrapper = shallow(<Radio />);
  });

  it("renders correctly", () => {
    expect(wrapper).toBeDefined();
  });
  // wrapper.find(thing).props.whatever we want;
  it("name is not defined ", () => {
    expect(wrapper.find("input").props().name).toBeUndefined();
  });

  it("value is not defined ", () => {
    expect(wrapper.find("input").props().value).toBeUndefined();
  });

  it("id is not defined ", () => {
    expect(wrapper.find("input").props().id).toBeUndefined();
  });
  it("onChange is not defined ", () => {
    expect(wrapper.find("input").props().onChange).toBeUndefined();
  });

  it("htmlFor is not defined ", () => {
    expect(wrapper.find("label").props().htmlFor).toBeUndefined();
  });
});

describe("Radio Component with name", () => {
  let wrapper;
  beforeEach(() => {
    wrapper = shallow(<Radio name="type" />);
  });

  it("renders correctly", () => {
    expect(wrapper).toBeDefined();
  });
  // wrapper.find(thing).props.whatever we want;
  it("name is defined ", () => {
    expect(wrapper.find("input").props().name).toEqual("type");
  });

  it("value is not defined ", () => {
    expect(wrapper.find("input").props().value).toBeUndefined();
  });

  it("id is not defined ", () => {
    expect(wrapper.find("input").props().id).toBeUndefined();
  });
  it("onChange is not defined ", () => {
    expect(wrapper.find("input").props().onChange).toBeUndefined();
  });

  it("htmlFor is not defined ", () => {
    expect(wrapper.find("label").props().htmlFor).toBeUndefined();
  });
});

describe("Radio Component with name,value", () => {
  let wrapper;
  beforeEach(() => {
    wrapper = shallow(<Radio name="type" value="OAuth" />);
  });

  it("renders correctly", () => {
    expect(wrapper).toBeDefined();
  });
  // wrapper.find(thing).props.whatever we want;
  it("name is defined ", () => {
    expect(wrapper.find("input").props().name).toEqual("type");
  });

  it("value is defined ", () => {
    expect(wrapper.find("input").props().value).toEqual("OAuth");
  });

  it("id is not defined ", () => {
    expect(wrapper.find("input").props().id).toBeUndefined();
  });
  it("onChange is not defined ", () => {
    expect(wrapper.find("input").props().onChange).toBeUndefined();
  });

  it("htmlFor is not defined ", () => {
    expect(wrapper.find("label").props().htmlFor).toBeUndefined();
  });
});

describe("Radio Component with name,value,id and htmlFor", () => {
  let wrapper;
  beforeEach(() => {
    wrapper = shallow(
      <Radio name="type" value="OAuth" id="defaultGroupExample1" />
    );
  });

  it("renders correctly", () => {
    expect(wrapper).toBeDefined();
  });
  // wrapper.find(thing).props.whatever we want;
  it("name is defined ", () => {
    expect(wrapper.find("input").props().name).toEqual("type");
  });

  it("value is defined ", () => {
    expect(wrapper.find("input").props().value).toEqual("OAuth");
  });

  it("id is  defined ", () => {
    expect(wrapper.find("input").props().id).toEqual("defaultGroupExample1");
  });
  it("onChange is not defined ", () => {
    expect(wrapper.find("input").props().onChange).toBeUndefined();
  });

  it("htmlFor is  defined ", () => {
    expect(wrapper.find("label").props().htmlFor).toEqual(
      "defaultGroupExample1"
    );
  });
});

describe("Radio Component with name,value,id and htmlFor and onChange", () => {
  const onC = jest.fn();
  let wrapper;
  beforeEach(() => {
    wrapper = shallow(
      <Radio
        name="type"
        value="OAuth"
        id="defaultGroupExample1"
        onChange={onC}
      />
    );
  });

  it("renders correctly", () => {
    expect(wrapper).toBeDefined();
  });
  // wrapper.find(thing).props.whatever we want;
  it("name is defined ", () => {
    expect(wrapper.find("input").props().name).toEqual("type");
  });

  it("value is defined ", () => {
    expect(wrapper.find("input").props().value).toEqual("OAuth");
  });

  it("id is  defined ", () => {
    expect(wrapper.find("input").props().id).toEqual("defaultGroupExample1");
  });
  it("onChange is defined ", () => {
    expect(wrapper.find("input").props().onChange).toBeUndefined();
  });

  it("htmlFor is  defined ", () => {
    expect(wrapper.find("label").props().htmlFor).toEqual(
      "defaultGroupExample1"
    );
  });
});
