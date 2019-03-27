var password = "d093dk2qp309r2Q)#@(RKOP#@)(RF@#()ww";
var textToEncrypt = "{'cpf':'12345678900'}";
var jwt = require('jsonwebtoken');
var md5 = require('md5'); 

var encrypt = function (plain_text, password) {
    let encryptionMethod = 'AES-256-CBC';
    let secret = md5(password); //must be 32 char length
    let iv = secret.substr(0,16);
    let crypto = require('crypto');
    let encryptor = crypto.createCipheriv(encryptionMethod, secret, iv);
    let data = encryptor.update(plain_text, 'utf8', 'base64') + encryptor.final('base64');
    return jwt.sign({ data: data }, secret);
};

var decrypt = function (token, password) {
    let secret = md5(password); //must be 32 char length
    let decoded = jwt.verify(token, secret);
    let encryptedMessage = decoded.data;
    let encryptionMethod = 'AES-256-CBC';       
    let iv = secret.substr(0,16);
    let crypto = require('crypto');
    let decryptor = crypto.createDecipheriv(encryptionMethod, secret, iv);
    return decryptor.update(encryptedMessage, 'base64', 'utf8') + decryptor.final('utf8');
};

var encryptedMessage = encrypt(textToEncrypt, password);
//var encryptedMessage = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiVUlkcmVIeElPSzl2dEh4QVJMN1RUcmZ2MXgyUUpWa2trV21ZYWQ5am1WUT0ifQ.6kvzIriaUhYhM9b7-gcohftXbD5ly95ixlfdmz5EH6k';
var decryptedMessage = decrypt(encryptedMessage, password);

console.log(`Original msg: ${textToEncrypt}`);
console.log(`Encypted msg: ${encryptedMessage}`);
console.log(`Decypted msg: ${decryptedMessage}`);
