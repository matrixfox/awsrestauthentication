/*
  Created by: railroadmanuk
  Modified by: matrixfox

  Version: 0.1

  Description: I had to modify the canonical request then add a gateway api key to the header.

  http://docs.aws.amazon.com/apigateway/api-reference/signing-requests/
*/

// declare our dependencies
var crypto = require('crypto-js');
var https = require("https");

// our variables
const config = {
  access_key : "....................",
  secret_key : "....................",
  api_key    : "....................",
  region     : "us-east-1",
  url        : "api.us-east-1.amazonaws.com",
  awsPath    : "/prod/lambdaDBFunc",
  awsService : "execute-api",
  awsMethod  : "POST"
}

// get the various date formats needed to form our request
var amzDate = getAmzDate(new Date().toISOString());
var authDate = amzDate.split("T")[0];

// we have a payload here because it is a POST request
var payload = '{"TableName": "dynamodbName","Item": {"itemName": "Bob"}}';
// get the SHA256 hash value for our payload
var hashedPayload = crypto.SHA256(payload).toString();

// create our canonical request
var canonicalReq =  config.awsMethod + '\n' +
                    config.awsPath + '\n' +
                    '\n' +
                    'content-type:' + 'application/x-www-form-urlencoded' + '\n' +
                    'host:' + config.url + '\n' +
                    'x-amz-date:' + amzDate + '\n' +
                    'x-api-key:' + config.api_key + '\n' +
                    '\n' +
                    'content-type;host;x-amz-date;x-api-key' + '\n' +
                    hashedPayload;

// hash the canonical request
var canonicalReqHash = crypto.SHA256(canonicalReq).toString();

// form our String-to-Sign
var stringToSign =  'AWS4-HMAC-SHA256\n' +
                    amzDate + '\n' +
                    authDate+'/'+config.region+'/'+config.awsService+'/aws4_request\n'+
                    canonicalReqHash;

// get our Signing Key
var signingKey = getSignatureKey(crypto, config.secret_key, authDate, config.region, config.awsService);

// Sign our String-to-Sign with our Signing Key
var authKey = crypto.HmacSHA256(stringToSign, signingKey);

// Form our authorization header
var authString =  'AWS4-HMAC-SHA256 ' +
                  'Credential='+
                  config.access_key+'/'+
                  authDate+'/'+
                  config.region+'/'+
                  config.awsService+'/aws4_request, '+
                  'SignedHeaders=content-type;host;x-amz-date;x-api-key, '+
                  'Signature='+authKey;

// throw our headers together
headers = {
  "content-type": "application/x-www-form-urlencoded",
  "x-api-key": config.api_key,
  "x-amz-date": amzDate,
  "authorization": authString,
  "cache-control": "no-cache"
};


// call our function
performRequest(config.url, headers, payload);


// this function gets the Signature Key, see AWS documentation for more details, this was taken from the AWS samples site
function getSignatureKey(Crypto, key, dateStamp, regionName, serviceName) {
    var kDate = Crypto.HmacSHA256(dateStamp, "AWS4" + key);
    var kRegion = Crypto.HmacSHA256(regionName, kDate);
    var kService = Crypto.HmacSHA256(serviceName, kRegion);
    var kSigning = Crypto.HmacSHA256("aws4_request", kService);
    return kSigning;
}

// this function converts the generic JS ISO8601 date format to the specific format the AWS API wants
function getAmzDate(dateStr) {
  var chars = [":","-"];
  for (var i=0;i<chars.length;i++) {
    while (dateStr.indexOf(chars[i]) != -1) {
      dateStr = dateStr.replace(chars[i],"");
    }
  }
  dateStr = dateStr.split(".")[0] + "Z";
  return dateStr;
}

// the REST API call using the Node.js 'https' module
function performRequest(endpoint, headers, data) {

  var dataString = data;

  var options = {
    host: endpoint,
    port: 443,
    path: config.awsPath,
    method: config.awsMethod,
    headers: headers
  };

  var req = https.request(options, function(res) {
    res.setEncoding('utf-8');

    var responseString = '';

    res.on('data', function(data) {
      responseString += data;
    });

    res.on('end', function() {
      console.log(responseString);
    });
  });

  req.write(dataString);
  req.end();

}
