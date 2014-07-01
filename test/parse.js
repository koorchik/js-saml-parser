'use strict';

var SAMLParser = require('./../lib/SAMLParser');
var fs = require('fs');

// console.log(__dirname + '/fixtures/valid_saml_token.xml');
var validTokenStr = fs.readFileSync( __dirname + '/fixtures/valid_saml_token.xml' ).toString();

var parser = new SAMLParser({namespace: 'ns2'});
parser.parse(validTokenStr);