package fr.paris.lutece.util.jwt.service;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;



/*
 * Copyright (c) 2002-2018, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */

public class JWTUtilTest 
{
    private static final String HEADER = "{\n" +
    "  \"typ\": \"JWT\",\n" +
    "  \"alg\": \"RS256\",\n" +
    "  \"x5t\": \"NmJmOGUxMzZlYjM2ZDRhNTZlYTA1YzdhZTRiOWE0NWI2M2JmOTc1ZA==\"\n" +
    "}";
    private static final String PAYLOAD = "{\n" +
    "  \"iss\": \"wso2.org/products/am\",\n" +
    "  \"exp\": 1552984468352,\n" +
    "  \"http://wso2.org/claims/subscriber\": \"admin\",\n" +
    "  \"http://wso2.org/claims/applicationid\": \"2\",\n" +
    "  \"http://wso2.org/claims/applicationname\": \"MyDashboard\",\n" +
    "  \"http://wso2.org/claims/applicationtier\": \"Unlimited\",\n" +
    "  \"http://wso2.org/claims/apicontext\": \"/identity/v2\",\n" +
    "  \"http://wso2.org/claims/version\": \"v2\",\n" +
    "  \"http://wso2.org/claims/tier\": \"Unlimited\",\n" +
    "  \"http://wso2.org/claims/keytype\": \"SANDBOX\",\n" +
    "  \"http://wso2.org/claims/usertype\": \"APPLICATION\",\n" +
    "  \"http://wso2.org/claims/enduser\": \"admin@carbon.super\",\n" +
    "  \"http://wso2.org/claims/enduserTenantId\": \"-1234\"\n" +
    "}";
    private static final String PUB_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlJTEugcELoXjR0Kg8bFavTIpjiKVMAiIyqexpUYV3IkuoEFDQn/mV2V6sZc1ce4h4BUf5OPH9IQ0Ci7+iXmnIr6FRmcz63quugl+HNdZIuEMXCPQb2XYTjZYmXtOxnYFOF3ds7eRwUAiFI3wXNaqxyn6PQeP89Tz+3igj1PGDteKmzY/6ZL/BY4JEqQHJ2ST8MzIleR7RZh9iZPT9zjwts61J+NH7rqbG11F7bW21wHhMX+A8iCdheh26pphU8vleCT+nhPD5tNP7tQ6HpGQiu1pIhRLxKbByQXJTYkUMjP66EEnBOrtzaCiSKXyLqTPD2bTBybwYdhefBEXrMzqbwIDAQAB";
    private static final String PRIV_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCUlMS6BwQuheNHQqDxsVq9MimOIpUwCIjKp7GlRhXciS6gQUNCf+ZXZXqxlzVx7iHgFR/k48f0hDQKLv6JeacivoVGZzPreq66CX4c11ki4QxcI9BvZdhONliZe07GdgU4Xd2zt5HBQCIUjfBc1qrHKfo9B4/z1PP7eKCPU8YO14qbNj/pkv8FjgkSpAcnZJPwzMiV5HtFmH2Jk9P3OPC2zrUn40fuupsbXUXttbbXAeExf4DyIJ2F6HbqmmFTy+V4JP6eE8Pm00/u1DoekZCK7WkiFEvEpsHJBclNiRQyM/roQScE6u3NoKJIpfIupM8PZtMHJvBh2F58EReszOpvAgMBAAECggEAK1zBj0MV8tfrTTRCUVc/0qCNpSgtnw+WkIJhY4kxPyQgIe/6B7HZER+SL7sgA2iKpWG05bGefRuKLoCpk4iYARlWPwZGjk5HKQ81KYilwHqqh0eCgMhZ2PWeZOiqRFxUSK+IUPddh+dGKvaDtCyIOcjj+aS32+MF85mwTjQWROUr3oUddgEuqOrYJ5GgC91NnXvCgbnu+FPgn00/iaLFRdp7EaIaNFusGGf5lsEUL6He3uBUOEv96KXvYFfMuBUOLV4NiW3b4Vk5alNr4cbzizaP8/i+vR1uczJgoBnwL8AYZrQLnl7wPRH5SJ5GVM9wTFc44vyNdoogOeAzVV8FSQKBgQDMOmKPuJdDglgAnJJ27XWmlOtKwA0C8VHtgOdipnlapXP3GC9/AEZyFVKB0t2iP2XKi+1a0kxvyZo3WmnLOkte2ymsW+s51fGKovi06n9U1zhr5mSuF/225j5633ZPGTpzL+3Miq59Y5R8jGiVvobeOgopWyXhuCmZqurfQvIr+QKBgQC6PxyDkoBbpOuIl8YepRy+KvLRaKT7FhYVmlHN8eT9mIWYG5y9I+L4w7UJtVAq6H3u2Czfjybz6Y+cjH//BCL4jOddv9PWbchnRN95AeUK6ATn/4Gd9RhocTnk4SjiUfuHdHyS104QrJ6VUIbNiwsImce/68MpN3G2J3emODTTpwKBgQCOfuJMQ1CPkv+SFaz/+/lN7LQraMrrVbODUqCfrWYZAD5kluR06Z09dnEmEhoAXdnJNE69QuSATxsiKhyM5zS1j5eJIm2C4irxP3rmyINlj/FXH975tdWZ6xaHJynmUMT+n999CvpqlLODH3jNmq2Bmt+CMY3B63xjMuVEN/K/CQKBgFULmJOkBCTU7BCVbYx0zOkxZ2ukIyHcdf0rWIt4F56NVQOeKDZd+ripdTOXraHKRCcaY3M6RQk/76oGpjPmyalBfiza+XqC6u3tDzaMXPBb/lGJ5MAiOSEIAu22uxqNYRP7Zx8OXcFTcZ6xBL067rDgt8u1doqNnMkWwJYQOF8lAoGAJCh5yLyhdCPKDt3HUb87QKGa9Q1NrShdeMQ4XEifsVi7gdcUp5DgiSJydmXeNTivcPTjFMu1em8B3JE/nuU7HpSeH1Z7eDAsZjL1M9LoJDayOBwaEGWxV1Hh98wWPOTB4wV73Id/ZHyDR0Vg1ybBNEjV7c0IZEm0RCnNn/w1EjQ=";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    
    /**
     * Check a JWT building step by step and verify the RSA-built signature with JJWT lib
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws SignatureException 
     */
    @Test
    public void checkRSA256SignatureTest( ) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException, SignatureException
    {
        //Build a JWT encoded with a RSA private key
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIV_KEY));
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(PUB_KEY));
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        
        String strBase64UrlEncodeHeader = Base64.getUrlEncoder( ).encodeToString( HEADER.getBytes( "UTF-8" ) );
        String strBase64UrlEncodePayload= Base64.getUrlEncoder( ).encodeToString( PAYLOAD.getBytes( "UTF-8" ) );
        String strAssertion = strBase64UrlEncodeHeader + "." + strBase64UrlEncodePayload;

        
        Signature signature = Signature.getInstance( SHA256_WITH_RSA );
        signature.initSign( privKey);
        
        byte[] dataInBytes = strAssertion.getBytes( "UTF-8");
        signature.update( dataInBytes );
        byte[] signatureBytes = signature.sign( );
        
        String strBase64UrlEncodeSignature = Base64.getUrlEncoder( ).encodeToString( signatureBytes );
        
        String computedJWT = strAssertion+"."+strBase64UrlEncodeSignature;
        
        //Verify the JWT with the RSA corresponding private Key
        Assertions.assertTrue(  JWTUtil.checkSignature( computedJWT, pubKey ) );
    }
}
