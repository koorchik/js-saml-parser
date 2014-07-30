var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');
var xpath = xmlCrypto.xpath;

module.exports = function (assertion,  cert) {
    var fullXml = assertion.xml;
    var doc = new xmldom.DOMParser().parseFromString(fullXml);

    var decryptedAssertions = xpath(doc, "/*/*[local-name()='Assertion']");

    if (decryptedAssertions.length != 1) {
        throw new Error('Invalid EncryptedAssertion content')
    };

    var currentNode =  decryptedAssertions[0];

    var xpathSigQuery = ".//*[local-name(.)='Signature' and " +
                      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";

    var signatures = xpath(currentNode, xpathSigQuery);

    // This function is expecting to validate exactly one signature, so if we find more or fewer
    //   than that, reject.
    if (signatures.length != 1) {
        return false;
    }

    var signature = signatures[0].toString();
    var sig = new xmlCrypto.SignedXml();

    sig.keyInfoProvider = {
        getKeyInfo: function (key) {
            return "<X509Data></X509Data>";
        },
        getKey: function (keyInfo) {
            return certToPEM(cert);
        }
    };

    sig.loadSignature(signature);
    // We expect each signature to contain exactly one reference to the top level of the xml we
    //   are validating, so if we see anything else, reject.

    if (sig.references.length != 1 ) {
        return false;
    }

    var refUri = sig.references[0].uri;
    var refId = (refUri[0] === '#') ? refUri.substring(1) : refUri;
    // If we can't find the reference at the top level, reject

    var idAttribute = currentNode.getAttribute('ID') ? 'ID' : 'Id';

    if (currentNode.getAttribute(idAttribute) != refId) {
        return false;
    }

    // If we find any extra referenced nodes, reject.  (xml-crypto only verifies one digest, so
    //   multiple candidate references is bad news)
    var totalReferencedNodes = xpath(currentNode.ownerDocument, "//*[@" + idAttribute + "='" + refId + "']");

    if (totalReferencedNodes.length > 1){
        return false;
    }

    return sig.checkSignature(fullXml);
};

function certToPEM(cert) {
    cert = cert.match(/.{1,64}/g).join('\n');

    if (cert.indexOf('-BEGIN CERTIFICATE-') === -1){
        cert = "-----BEGIN CERTIFICATE-----\n" + cert;
    }

    if (cert.indexOf('-END CERTIFICATE-') === -1){
        cert = cert + "\n-----END CERTIFICATE-----\n";
    }

    return cert;
};