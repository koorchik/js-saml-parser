'use strict';

var SAMLParser = require('./../lib/SAMLParser');
var SAMLValidator = require('./../lib/SAMLValidator');

var fs = require('fs');
var util = require('util');

// console.log(__dirname + '/fixtures/valid_saml_token.xml');
var validTokenStr = fs.readFileSync( __dirname + '/fixtures/valid_saml_token.xml' ).toString();

var parser = new SAMLParser({ namespace: 'ns2' });
var validator = new SAMLValidator();

parser.parse(validTokenStr).then(function(assertion) {
    // console.log(util.inspect(assertion, { depth: 100 }));
    return validator.validate(assertion);
}).then(function(validAssertion) {
    // console.log(util.inspect(validAssertion, {depth: 100}));
}).catch(console.error);

