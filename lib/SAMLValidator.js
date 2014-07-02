'use strict';

var Promise = require('es6-promises');
var crypto = require('crypto');
var xmldom = require('xmldom');
var xmlCrypto = require('xml-crypto');

function SAMLValidator() {

}

SAMLValidator.prototype = {
    validate: function(assertion) {
        return new Promise(function(resolve, reject) {
            try {
                this._validateSignature(assertion);
                // this._validateExpiration(assertion);
                this._validateAudience(assertion);
                resolve(assertion);
            } catch (e) {
                reject(e);
            }
        }.bind(this));
    },

    _validateSignature: function(assertion) {
        var thumbprint = this._calculateThumbprint(assertion.signature.SignatureValue);
        console.log(thumbprint);
    },

    _validateExpiration: function(assertion) {
        var notBefore = assertion.conditions.NotBefore;
        var notOnOrAfter = assertion.conditions.NotOnOrAfter;
        var now = new Date();

        console.log(now, notOnOrAfter);
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

    _validateAudience: function() {

    },


    _calculateThumbprint: function(signature) {
        var shasum = crypto.createHash('sha1');

        var binary = new Buffer(signature, 'base64').toString('binary');

        shasum.update(binary);

        return shasum.digest('hex');
    }
};



module.exports = SAMLValidator;