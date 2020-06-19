import axios from "axios";

const BASE_URL = "http://localhost:8081";

export const getCacheToken = (credentials) => {
  const requestString = `${BASE_URL}/token`;
  return axios.post(requestString, credentials).catch((error) => ({
    type: "GET_CREDENTIAL_TOKEN_FAIL",
    error,
  }));
};
