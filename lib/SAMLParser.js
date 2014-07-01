'use strict';

var xml2js = require('xml2js');
var util = require('util');

function SAMLParser(args) {
    args = args || { namespace: 'saml' };

    this.namespace = args.namespace || 'samle';

    this.xmlParser = new xml2js.Parser({
        async: true,
        attrkey: '$',
        charkey: '_',
        explicitArray: true
    });
}

SAMLParser.prototype = {
    parse: function(assertionXML) {
        var self = this;

        this.xmlParser.parseString(assertionXML, function(err, result) {
            var rawAssertion = result.Response[self._ns('Assertion')][0];

            var assertion = {
                issuer:     self._extractIssuer(rawAssertion),
                attributes: self._extractAttributes(rawAssertion),
                conditions: self._extractConditions(rawAssertion),
                authn:      self._extractAuthn(rawAssertion),
                signature:  self._extractSignature(rawAssertion),
            };

            console.log(util.inspect(assertion, {depth: 100}));
        });
    },

    _ns: function(attr) {
        if (this.namespace) {
            return  this.namespace + ':' + attr;
        } else {
            return attr;
        }
    },

    _extractIssuer: function(rawAssertion) {
        return rawAssertion[this._ns('Issuer')][0]._;
    },

    _extractAttributes: function(rawAssertion) {
        var ns = this._ns.bind(this);
        var attributes = {};

        var rawAttributesAssertion = rawAssertion[ns('AttributeStatement')];

        if ( rawAttributesAssertion ) {
            var rawAttributes = rawAttributesAssertion[0][ ns('Attribute') ];

            if (rawAttributes) {
                rawAttributes  = Array.isArray(rawAttributes) ? rawAttributes : [rawAttributes];

                rawAttributes.forEach(function (rawAttribute) {
                    attributes[ rawAttribute.$.Name ] = rawAttribute[ ns('AttributeValue') ][0];
                });
            }
        }

        return attributes;
    },

    _extractConditions: function(rawAssertion) {
        var ns = this._ns.bind(this);

        var rawConditions = rawAssertion[ns('Conditions')];
        if (!rawConditions) return {};

        return  {
            NotBefore:    new Date(rawConditions[0].$.NotBefore),
            NotOnOrAfter: new Date(rawConditions[0].$.NotOnOrAfter),
            Audience:     rawConditions[0][ns('AudienceRestriction')][0][ns('Audience')][0]
        };

    },

    _extractAuthn: function(rawAssertion) {
        var ns = this._ns.bind(this);

        var rawAuthn = rawAssertion[ns('AuthnStatement')];
        if (!rawAuthn) return {};

        return  {
            AuthnInstant:         new Date(rawAuthn[0].$.AuthnInstant),
            SessionIndex:         rawAuthn[0].$.SessionIndex,
            AuthnContextClassRef: rawAuthn[0][ns('AuthnContext')][0][ns('AuthnContextClassRef')][0]
        };
    },

    _extractSignature: function(rawAssertion) {
        var rawSignature = rawAssertion['ds:Signature'];
        if (!rawSignature) return null;

        return {
            SignatureValue: rawSignature[0]['ds:SignatureValue'][0]._,
            X509Certificate: rawSignature[0]['ds:KeyInfo'][0]['ds:X509Data'][0]['ds:X509Certificate'][0]._
        };
    }
};


module.exports = SAMLParser;