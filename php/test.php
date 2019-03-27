<?php
require "vendor\autoload.php";
use \Firebase\JWT\JWT;

$password = "d093dk2qp309r2Q)#@(RKOP#@)(RF@#()ww";
$msg = "{'cpf':'12345678900'}";

function encrypt($msg, $password){

    $secret = hash("md5",$password);  //must be 32 char length    
    $encryptionMethod = "AES-256-CBC";
    $iv = substr($secret, 0, 16);
    $data = openssl_encrypt($msg, $encryptionMethod, $secret,0,$iv);
    $token = ["data" => $data];
    return JWT::encode($token, $secret);    
}

function decrypt($token, $password){

    $secret = hash("md5",$password);  //must be 32 char length
    $decoded = JWT::decode($token, $secret, array('HS256'));    
    $msg = $decoded->data;  
    $encryptionMethod = "AES-256-CBC";    
    $iv = substr($secret, 0, 16);
    return openssl_decrypt($msg, $encryptionMethod, $secret,0,$iv);
}


$encryptedMessage = encrypt($msg, $password);
//$encryptedMessage = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiVUlkcmVIeElPSzl2dEh4QVJMN1RUcmZ2MXgyUUpWa2trV21ZYWQ5am1WUT0ifQ.6kvzIriaUhYhM9b7-gcohftXbD5ly95ixlfdmz5EH6k';
$decryptedMessage = decrypt($encryptedMessage, $password);

echo "Original msg: $msg\n";
echo "Encypted msg: $encryptedMessage\n";
echo "Decypted msg: $decryptedMessage\n";
