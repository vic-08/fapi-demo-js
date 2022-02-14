const config = require('./config').Config;
const { Issuer, custom} = require('openid-client')
const { uuid } = require('uuidv4');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require("path");
const TokenService = require('../services/oauth/tokenService');
const HTTPUtil = require('../services/httputil');
const resourceClient = new HTTPUtil(config.resourceBase);

let tokenService = new TokenService();

class OAuthController {

    constructor(scope) {
        this._scope = scope;
        this._jwks = null;
        this._cert = null;
        this._key = null;
        
        try {
            const data = fs.readFileSync(path.resolve(__dirname, `../../config/jwks.json`), 'utf8');
            this._jwks = { "keys": JSON.parse(data) };
        } catch (err) {
            console.error(err);
        }
        
        try {
            this._cert = fs.readFileSync(path.resolve(__dirname, "../../config/cert.pem"), 'utf8');
        } catch (err) {
            console.error(err);
        }

        try {
            this._key = fs.readFileSync(path.resolve(__dirname, `../../config/key.pem`), 'utf8');
        } catch (err) {
            console.error(err);
        }
    }

    authorize = async (req, res) => {

        this._oidcIssuer = await Issuer.discover(config.discoveryUrl);
        console.log('Discovered issuer %s %O', this._oidcIssuer.issuer, this._oidcIssuer.metadata);

        // lodge an intent first
        let intentID = "";

        try {
            let intentData = await this._lodgeIntent(req, res, this._oidcIssuer.metadata.issuer);
            console.log(`DEBUG: intentData=${JSON.stringify(intentData)}`)
            intentID = intentData.ConsentId;
            if (intentID == "") {
                res.send("Unable to lodge the intent though some data was returned");
                return;
            }
        } catch (e) {
            console.error("Error occurred while trying to lodge the intent; " + e);
            res.send("Unable to lodge the intent");
            return;
        }

        this._client = new this._oidcIssuer.FAPI1Client({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            redirect_uris: [config.redirectUri],
            response_types: ['code'],
            token_endpoint_auth_method: (config.mtlsOrJWT == "mtls") ? 'tls_client_auth' : "private_key_jwt",
            token_endpoint_auth_signing_alg: 'RS256',
            tls_client_certificate_bound_access_tokens: config.certBound,
            id_token_signed_response_alg: 'RS256',
        }, this._jwks);

        var clientAssertionPayload = null
        if (config.mtlsOrJWT != "mtls") {
            let aud = this._oidcIssuer.metadata.token_endpoint;
            /*
            if (this._oidcIssuer.metadata.mtls_endpoint_aliases) {
                aud = this._oidcIssuer.metadata.mtls_endpoint_aliases.token_endpoint;
            }
            */
            clientAssertionPayload = { 
                sub: config.clientId, 
                iss: config.clientId,
                jti: uuid(),
                iat: new Date().getTime()/1000,
                exp: (new Date().getTime() + 30 * 60 * 1000)/1000,
                aud: aud,
            }
        }

        if (config.certBound || config.mtlsOrJWT == "mtls") {
            const key = this._key;
            const cert = this._cert;
            this._client[custom.http_options] = () => ({ key, cert });
        }
        
        let parData = await this._client.pushedAuthorizationRequest({
            scope: config.scope,
            state: uuid(),
            claims: {
                "userinfo": {
                    "openbanking_intent_id": { "value": intentID, "essential": true }
                },
                "id_token": {
                    "openbanking_intent_id": { "value": intentID, "essential": true }
                }
            },
        }, {
            clientAssertionPayload: clientAssertionPayload,
        });

        let url = this._client.authorizationUrl({
            request_uri: parData.request_uri,
        });
        
        res.redirect(url)
    }

    aznCallback = async (req, res) => {
        const params = this._client.callbackParams(req);
        var clientAssertionPayload = null
        if (config.mtlsOrJWT != "mtls") {
            let aud = this._oidcIssuer.metadata.token_endpoint;
            if (this._oidcIssuer.metadata.mtls_endpoint_aliases) {
                aud = this._oidcIssuer.metadata.mtls_endpoint_aliases.token_endpoint;
            }
            clientAssertionPayload = { 
                sub: config.clientId, 
                iss: config.clientId,
                jti: uuid(),
                iat: new Date().getTime()/1000,
                exp: (new Date().getTime() + 30 * 60 * 1000)/1000,
                aud: aud,
            }
        }
        const tokenSet = await this._client.callback(config.redirectUri, params, {
            state: params.state
        }, {
            clientAssertionPayload: clientAssertionPayload,
        });
        console.log('received and validated tokens %j', tokenSet);
        console.log('validated ID Token claims %j', tokenSet.claims());

        req.session.authToken = tokenSet;
        req.session.token = tokenSet;
        req.session.save();

        // Extract redirect URL from querystring
        let targetUrl = req.session.targetUrl;
        if (!targetUrl || targetUrl == "") {
            targetUrl = "/";
        }

        // redirect to authenticated page
        res.redirect(targetUrl);
    }

    logout = (req, res) => {

        if (!OAuthController.isLoggedIn(req)) {
            res.redirect('/')
            return;
        }

        let authToken = OAuthController.getAuthToken(req);
        this._authClient.revokeToken(authToken, 'access_token').then(response => {

        }).catch(error => {
            console.log(error);
        })
        
        // revoking the refresh_token
        this._authClient.revokeToken(authToken, 'refresh_token').then(response => {
        
        }).catch(error => {
            console.log(error);
        })

        req.session.destroy();
        const proxyHost = req.headers["x-forwarded-host"];
        const host = proxyHost ? proxyHost : req.headers.host;
        res.redirect('https://' + config.tenantUrl + '/idaas/mtfim/sps/idaas/logout?redirectUrl=' + encodeURIComponent(req.protocol + '://' + host) + "&themeId=" + config.themeId);
    }

    _lodgeIntent = async (req, res, issuer) => {
        let tokenData = await tokenService.getToken('payment')
        console.log(`DEBUG: issuer=${issuer}, tokenData=${JSON.stringify(tokenData)}`);

        let response = await resourceClient.post('/domestic-payments', {
                "type": "payment_initiation",
                "actions": [
                    "initiate",
                    "status",
                    "cancel"
                ],
                "locations": [
                    "https://example.com/payments"
                ],
                "instructedAmount": {
                    "currency": "EUR",
                    "amount": "123.50"
                },
                "creditorName": "Merchant A",
                "creditorAccount": {
                    "iban": "DE02100100109307118603"
                },
                "remittanceInformationUnstructured": "Ref Number Merchant"
            }, {
                "Accept": "application/json",
                "tenant": config.tenantUrl,
                "Authorization": "Bearer " + tokenData.access_token,
            });

        console.log(`DEBUG: consentResult=${JSON.stringify(response.data)}`);
        return response.data;
    }

    static isLoggedIn(req) {
        return req.session != null && req.session.authToken != null && req.session.authToken != "";
    }

    static getAuthToken = (req) => {
        if (req.session) {
            return req.session.authToken
        }
    
        return null;
    }
}

module.exports = OAuthController;