'use strict';

var SAMLParser = require('./../lib/SAMLParser');
var SAMLValidator = require('./../lib/SAMLValidator');

var fs    = require('fs');
var util  = require('util');
var sinon = require('sinon');

// console.log(__dirname + '/fixtures/valid_saml_token.xml');
var validTokenStr = fs.readFileSync( __dirname + '/fixtures/valid_saml_token.xml' ).toString();

var parser = new SAMLParser({ namespace: 'ns2' });
var validator = new SAMLValidator();
var cert = fs.readFileSync(__dirname + '/fixtures/cert.cer').toString();

parser.parse( validTokenStr ).then(function(assertion) {
    // console.log(util.inspect(assertion, { depth: null }));

    var validationOptions = {
        audience: 'gskvaccinesmodelsonweb-tst',
        publicKey: cert
    };

    sinon.useFakeTimers( new Date('2014-06-23T17:30:30Z').getTime() );

    return validator.validate(assertion, validationOptions);
}).then(function(validAssertion) {
    console.log(util.inspect(validAssertion.attributes, {depth: 100}));
}).catch(console.error);

