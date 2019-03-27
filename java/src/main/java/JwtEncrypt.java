import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.*;
import java.math.*;

public class JwtEncrypt {
    public static void main(String... args){
        String key = "d093dk2qp309r2Q)#@(RKOP#@)(RF@#()ww";
        String originalString = "{'cpf':'12345678900'}";
        System.out.println("Original String to encrypt - " + originalString);
        String encryptedString = encrypt(originalString, key);
        System.out.println("Encrypted String - " + encryptedString);
        String decryptedString = decrypt(encryptedString, key);
        System.out.println("After decryption - " + decryptedString);
    }

    public static String encrypt(String value, String key)  {
        try {
            //Encriptando
            String md5key = JwtEncrypt.md5(key);
            String initVector = md5key.substring(0,16);
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(md5key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            String encMsg = Base64.getEncoder().encodeToString(encrypted);
            //Criando JWT
            try {
                Algorithm algorithm = Algorithm.HMAC256(md5key);
                String token = JWT.create()
                        .withClaim("data", encMsg)
                        .sign(algorithm);
                return token;
            } catch (JWTCreationException exception){
                //Invalid Signing configuration / Couldn't convert Claims.
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String token, String key) {
        String md5key = JwtEncrypt.md5(key);
        String initVector = md5key.substring(0,16);
        //VerifyJWT
        try {
            Algorithm algorithm = Algorithm.HMAC256(md5key);
            JWTVerifier verifier = JWT.require(algorithm)
                    .build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(token);
            String data = jwt.getClaim("data").asString();
            //Decrypt data
            try {
                IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(md5key.getBytes("UTF-8"), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                byte[] original = cipher.doFinal(Base64.getDecoder().decode(data));

                return new String(original);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        } catch (JWTVerificationException exception){
            //Invalid signature/claims
        }
        return null;
    }

    public static String md5(String s) {
        MessageDigest m= null;
        try {
            m = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        m.update(s.getBytes(),0,s.length());
        return new BigInteger(1,m.digest()).toString(16);
    }
}
