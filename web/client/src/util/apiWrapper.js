import axios from "axios";

const BASE_URL = process.env.BACKEND_URL ?? "http://localhost:8081";

export const getCacheToken = (credentials) => {
  const requestString = `${BASE_URL}/token`;
  return axios
    .get(requestString, {
      credentials,
      headers: {
        "Content-Type": "application/JSON",
      },
    })
    .catch((error) => ({
      type: "GET_CREDENTIAL_TOKEN_FAIL",
      error,
    }));
};
