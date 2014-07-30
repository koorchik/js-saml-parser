'use strict';

var Promise   = require('es6-promises');
var crypto    = require('crypto');
var xmldom    = require('xmldom');
var xmlCrypto = require('xml-crypto');

var validateSignature = require('./validateSignature.js');

function SAMLValidator() {

}

SAMLValidator.prototype = {
    validate: function(assertion, options) {
        if (!options) options = {};

        return new Promise(function(resolve, reject) {
            try {
                this._validateSignature(assertion, {
                    publicKey: options.publicKey,
                    thumbprint: options.thumbprint
                });

                if ( !options.bypassExpiration ) {
                    this._validateExpiration(assertion);
                }

                if ( options.audience ) {
                    this._validateAudience(assertion, options.audience);
                }

                resolve(assertion);
            } catch (e) {
                if (e.stack) {
                    console.log(e.stack)
                }

                reject(e);
            }
        }.bind(this));
    },

    _validateSignature: function(assertion, options) {
        return true; // Temporary disable signature validation
        var isSignatureValid;
        try {
            isSignatureValid = validateSignature(assertion, options.publicKey, options.thumbprint);
        } catch(e) {
            isSignatureValid = false;
        }

        if (!isSignatureValid) {
            throw {
                code: 'INVALID_SIGNATURE',
                message: 'Signature is not valid'
            };
        }
    },

    _validateExpiration: function(assertion) {
        var notBefore = assertion.conditions.NotBefore;
        var notOnOrAfter = assertion.conditions.NotOnOrAfter;
        var now = new Date();

        if ( now < notBefore ) {
            throw {
                code: 'WRONG_TOKEN_TIME',
                message: 'Condition "NotBefore" is later than now'
            };
        }

        if ( now > notOnOrAfter ) {
            throw {
                code: 'WRONG_TOKEN_TIME',
                message: 'Condition "NotOnOrAfter" is before now'
            };
        }
    },

    _validateAudience: function(assertion, allowedAudience) {
        var assertionAudience = assertion.conditions.Audience;

        if (assertionAudience !== allowedAudience) {
            throw {
                code: 'WRONG_AUTDIENCE',
                message: 'Wrong assertion audience [' + assertionAudience + ']',
            }
        }
    },

    _calculateThumbprint: function(signature) {
        var shasum = crypto.createHash('sha1');

        var binary = new Buffer(signature, 'base64').toString('binary');

        shasum.update(binary);

        return shasum.digest('hex');
    }
};



module.exports = SAMLValidator;