import axios from 'axios';
const auth_api = axios.create({
  baseURL: window.location.origin,
});
auth_api.interceptors.request.use(
  (config) => {
    config.headers['Content-Type'] = 'application/json'
    return config;
  },
  (error) => Promise.reject(error)
);
auth_api.interceptors.response.use(
  async (response) => {
    return response.data.message;
  },
  async (error) => {
    if(error.response.data.error==='expired_token') {
      return window.location.reload()
    }

    return Promise.reject(error.response.data);
  }
);
export { auth_api };