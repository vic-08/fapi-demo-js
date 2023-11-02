// import dependencies and initialize the express router
const express = require('express');
const OAuthController = require('../controllers/oauth-controller');
const config = require('../controllers/config').Config;

const oauthController = new OAuthController(config.scope);
const router = express.Router();

// define routes
router.get('/',  (req, res) => {
    if (OAuthController.isTransactionComplete(req)) {
        console.log("[DEBUG] Transaction complete")
        res.render('payment', {title: 'Verify OIDC Demo', signupEnabled: false, signupLink: config.signupLink })
    } else if (OAuthController.isLoggedIn(req)) {
        console.log("[DEBUG] Logged in")
        res.render('payment', {title: 'Verify OIDC Demo', signupEnabled: false, signupLink: config.signupLink })
    } else {
        console.log("[DEBUG] Not logged in")
        res.render('index', {title: 'Verify OIDC Demo', signupEnabled: config.signupLink != "", signupLink: config.signupLink })
    }
});

router.get('/login', oauthController.authorize);
router.get('/logout', oauthController.logout)
router.get('/auth/callback', oauthController.aznCallback);

module.exports = router;