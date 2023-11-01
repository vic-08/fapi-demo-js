const config = require('./config').Config;
const { Issuer, custom, generators } = require('openid-client')
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
            intentID = intentData.ConsentId;
            if (intentID == "") {
                res.send("Unable to lodge the intent though some data was returned");
                return;
            }
        } catch (e) {
            console.error("Error occurred while trying to lodge the intent; " + e);
            console.error(e.stack);
            res.send("Unable to lodge the intent");
            return;
        }

        const code_verifier = generators.codeVerifier();
        const code_challenge = generators.codeChallenge(code_verifier);
        this._client = new this._oidcIssuer.FAPI1Client({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            redirect_uris: [config.redirectUri],
            response_types: ['code'],
            token_endpoint_auth_method: (config.mtlsOrJWT == "mtls") ? 'tls_client_auth' : "private_key_jwt",
            token_endpoint_auth_signing_alg: 'PS256',
            tls_client_certificate_bound_access_tokens: (config.certBound == "true"),
            id_token_signed_response_alg: 'PS256',
        }, this._jwks);

        var clientAssertionPayload = null
        if (config.mtlsOrJWT != "mtls") {
            let aud = this._oidcIssuer.metadata.issuer;
            clientAssertionPayload = { 
                sub: config.clientId, 
                iss: config.clientId,
                jti: uuid(),
                iat: new Date().getTime()/1000,
                exp: (new Date().getTime() + 30 * 60 * 1000)/1000,
                aud: aud,
            }
        }

        if (config.certBound == "true" || config.mtlsOrJWT == "mtls") {
            const key = this._key;
            const cert = this._cert;
            console.log("DEBUG: I am here for some reason");
            this._client[custom.http_options] = () => ({ key, cert });
        }
        
        let parReqData = {
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
        };

        console.log(`PAR request\n${JSON.stringify(parReqData, null, 2)}\n`)

        let parData = await this._client.pushedAuthorizationRequest(parReqData, {
            clientAssertionPayload: clientAssertionPayload,
        });

        console.log(`PAR response\n${JSON.stringify(parData, null, 2)}\n`);

        let url = this._client.authorizationUrl({
            request_uri: parData.request_uri,
            code_challenge,
            code_challenge_method: 'S256',
        });

        console.log(`Redirecting the browser to: ${url}\n`);

        req.session.currAction = "auth";
        if (req.query.action && req.query.action == "pay") {
            req.session.currAction = "pay";
        } else {
            req.session.payAuthIntentID = intentID;
        }
        req.session.codeVerifier = code_verifier;
        req.session.save();
        
        res.redirect(url)
    }

    aznCallback = async (req, res) => {
        console.log("Current action: " + req.session.currAction);
        var isPay = false;
        if (req.session.currAction && req.session.currAction == "pay") {
            isPay = true;
        }

        const params = this._client.callbackParams(req);
        var clientAssertionPayload = null
        if (config.mtlsOrJWT != "mtls") {
            let aud = this._oidcIssuer.metadata.token_endpoint;
            clientAssertionPayload = { 
                sub: config.clientId, 
                iss: config.clientId,
                jti: uuid(),
                iat: new Date().getTime()/1000,
                exp: (new Date().getTime() + 30 * 60 * 1000)/1000,
                aud: aud,
            }
        }

        console.log(`Validating with PKCE code verifier: ${req.session.codeVerifier}`);
        const tokenSet = await this._client.callback(config.redirectUri, params, {
            state: params.state,
            code_verifier: req.session.codeVerifier,
        }, {
            clientAssertionPayload: clientAssertionPayload,
        });
        console.log(`Received and validated tokens\n${JSON.stringify(tokenSet, null, 2)}\n`); 

        if (isPay) {
            req.session.trxAuthToken = tokenSet;
            req.session.trxToken = tokenSet;
        } else {
            req.session.authToken = tokenSet;
            req.session.token = tokenSet;
        }
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
        console.log(`Obtained token using 'client_credentials' grant flow:\n${JSON.stringify(tokenData, null, 2)}\n`);

        var isPay = false;
        if (req.query.action && req.query.action == "pay") {
            isPay = true;
        }

        var lodgeData;

        if (isPay) {
            lodgeData = {
                "type": "payment_transaction",
                "actions": [
                    "initiate",
                    "status",
                    "cancel"
                ],
                "locations": [
                    "https://example.com/payments"
                ],
                "instructedAmount": {
                    "currency": req.query.currency,
                    "amount": req.query.amount
                },
                "creditorName": "TrustMe Shop",
                "creditorAccount": {
                    "iban": "DE02100100109307118603"
                },
                "merchantAuthorizationId": req.session.payAuthIntentID
            }
            console.log(`Lodge an payment_initiation intent with the Bank\n${JSON.stringify(lodgeData, null, 2)}\n`);
        } else {
            lodgeData = {
                "type": "payment_initiation",
                "actions": [
                    "initiate",
                    "status",
                    "cancel"
                ],
                "locations": [
                    "https://example.com/payments"
                ],
                "creditorName": "TrustMe Shop",
                "creditorAccount": {
                    "iban": "DE02100100109307118603"
                }
            }
            console.log(`Lodge an merchant_auth intent with the Bank\n${JSON.stringify(lodgeData, null, 2)}\n`);
        }

        let response = await resourceClient.post('/domestic-payments', lodgeData, {
                "Accept": "application/json",
                "tenant": config.tenantUrl,
                "Authorization": "Bearer " + tokenData.access_token,
            });

        console.log(`Result of lodging an intent\n${JSON.stringify(response.data, null, 2)}\n`);
        return response.data;
    }

    static isLoggedIn(req) {
        return req.session != null && req.session.authToken != null && req.session.authToken != "" && (req.query.error == null || req.query.error != "dua_fail");
    }

    static isTransactionComplete(req) {
        return req.session != null && req.session.authToken != null && req.session.authToken != "" && req.session.trxAuthToken != null && req.session.trxAuthToken != "";
    }

    static getAuthToken = (req) => {
        if (req.session) {
            return req.session.authToken
        }
    
        return null;
    }
}

module.exports = OAuthController;