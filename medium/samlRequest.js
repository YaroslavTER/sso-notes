const moment = require('moment');
// for deflating SAML request
const pako = require('pako');
const uuid = require('uuid');
//.....
const config = {
  // domain of email address for identifying on client side if SAML is enable for same or not
  domain: 'outlook.com',
  // unique entityId while setting up SAML server
  entityURI: 'https://example.com',
  // SAML server login url, can be found in SAML XML file
  entryPoint:
    'https://login.microsoftonline.com/123456-xxxx-xxxx-xxxx-123456/saml2',
  // X 509 signing certificate, can be found in SAML XML file
  certificate:
    'MIIC8DCCAdigAwIBAgIQaKWqA3vVf7ZPHf5h52SkkjANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXMIIC8DCCAdigAwIBAgIQaKWqA3vVf7ZPHf5h52SkkjANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQX8MIIC8DCCAdigAwIBAgIQaKWqA3vVf7ZPHf5h52SkkjANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQX',
  // callback url after successfully authentication
  entityReplyUrl: 'https://example.com/api/auth/saml',
};
//.....
const generateSAMLRequest = (config) => {
  const SAMLReq = `<samlp:AuthnRequest
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    ID="${config.domain}${uuid.v4()}"
    Version="2.0"
    IssueInstant="${moment().utc().format()}"
    IsPassive="false"
    AssertionConsumerServiceURL="${
      config.entityReplyUrl
    }" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ForceAuthn="false">
      <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
        ${config.entityURI}
      </Issuer>
      <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">
      </samlp:NameIDPolicy>
    </samlp:AuthnRequest>`;
  const deflatedSAMLReq = pako.deflateRaw(SAMLReq);
  const deflatedBase64SAMLReq = Buffer(deflatedSAMLReq).toString('base64');
  const encodedDeflatedBase64SAMLReq = encodeURIComponent(
    deflatedBase64SAMLReq
  );
  return ~config.entryPoint.indexOf('?')
    ? `${config.entryPoint}&SAMLRequest=${encodedDeflatedBase64SAMLReq}`
    : `${config.entryPoint}?SAMLRequest=${encodedDeflatedBase64SAMLReq}`;
};
