const jwt = require('jsonwebtoken');
const OAuthController = require('./oauth-controller');
const Privacy = require('verify-privacy-sdk-js');
const config = require('./config').Config;
const TokenService = require('../services/oauth/tokenService')
const tokenService = new TokenService();

class UsersController {

    constructor() {}

    getUserPayload = (req) => {
        let authToken = OAuthController.getAuthToken(req);
        let decoded = jwt.decode(authToken.id_token);
        return decoded;
    }

    introspect = async (req) => {
        let authToken = OAuthController.getAuthToken(req);
        const data = await tokenService.introspect(authToken.access_token)
        console.log(`Introspection payload=\n${JSON.stringify(data, null, 2)}\n`);
        return data;
    };

    getUsersIndex = (req, res) => {
        if (!OAuthController.isLoggedIn(req)) {
            res.redirect('/');
            return null;
        }

        res.render('users', { user: this.getUserPayload(req), title: 'User Main' });
    }

    getProfile = async (req, res) => {
        if (!OAuthController.isLoggedIn(req)) {
            res.redirect('/');
            return;
        }

        let idTokenPayload = this.getUserPayload(req);
        let introspection = await this.introspect(req);
        res.render('profile', { user: idTokenPayload, fullJson: JSON.stringify(idTokenPayload, null, 2), introspection: JSON.stringify(introspection, null, 2), title: 'Profile Information' });
    }

    getConsents = (req, res) => {
        if (!OAuthController.isLoggedIn(req)) {
            res.redirect('/');
            return;
        }

        let idTokenPayload = this.getUserPayload(req);
        let auth = {
            accessToken: OAuthController.getAuthToken(req).access_token
        }

        let consentConfig = {
            tenantUrl: "https://" + config.tenantUrl
        }
        
        let dpcmClient = new Privacy(consentConfig, auth, {})
        dpcmClient.getUserConsents(auth).then(result => {
            // filter down to just the payment_initiation purpose
            let consents = result.consents.filter(x => x.purposeId == 'payment_initiation');
            console.log(`Consents for payment_initiation\n${JSON.stringify(consents, null, 2)}\n`)
            res.render('consents', { user: idTokenPayload, consents: consents, title: 'My Consents' });
        }).catch(err => {
            console.log("Error=" + err);
            res.render('consents', { user: idTokenPayload, consents: null, title: 'No consents found' });
        })
    }
}

module.exports = UsersController;