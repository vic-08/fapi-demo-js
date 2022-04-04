const config = require('../../controllers/config').Config;
const HTTPUtil = require('../httputil');
const httpClient = new HTTPUtil(`https://${config.tenantUrl}`);
        
class TokenService {

    getToken = async (scope) => {

        const response = await httpClient.post("/oauth2/token", {
            "grant_type": "client_credentials",
            "client_id": config.apiClientId,
            "client_secret": config.apiClientSecret,
            "scope": scope,
        }, {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        });

        return response.data;
    }

    introspect = async (accessToken) => {
        const response = await httpClient.post('/oauth2/introspect', {
            "client_id": config.apiClientId,
            "client_secret": config.apiClientSecret,
            "token": accessToken,
        }, {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        });

        return response.data;
    }
}

module.exports = TokenService;