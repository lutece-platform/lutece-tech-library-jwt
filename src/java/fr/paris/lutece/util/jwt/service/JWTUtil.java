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
package fr.paris.lutece.util.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 * Utils class for JWT
 */
public class JWTUtil
{
    protected static final Logger LOGGER = LogManager.getLogger( "lutece.security.jwt" );
    private static final String NO_SECURITY_ALG_HEADER = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.";

    /**
     * Checks claims key/value inside the JWT payload
     * 
     * @param request
     * @param strHeaderName
     * @param claimsToCheck
     * @return true if the key/values are present, false otherwise
     * @deprecated This method should not be used because there is no control over the signature of the token.
     */
    @Deprecated
    public static boolean checkUnsecuredPayloadValues( HttpServletRequest request, String strHeaderName, Map<String, String> claimsToCheck )
    {
        String strBase64JWT = request.getHeader( strHeaderName );

        // If no specific Header is provided, use spec JWT : try to fetch in Authorization: Bearer HTTP Header
        if ( strBase64JWT == null )
        {
            strBase64JWT = getAuthorizationBearerValue( request );
        }

        if ( strBase64JWT != null )
        {
            String strUnsecuredBase64JWT = getUnsecuredBase64JWT( strBase64JWT );
            try
            {
                Claims claims = Jwts.parser( ).unsecured( ).build( ).parseUnsecuredClaims( strUnsecuredBase64JWT ).getPayload( );
                
                for ( Entry<String, String> entry : claimsToCheck.entrySet( ) )
                {
                    if ( !claims.get( entry.getKey( ), String.class ).equals( entry.getValue( ) ) )
                    {
                        return false;
                    }
                }
            }
            catch( Exception e )
            {
                LOGGER.error( "Unable to check JWT payload for checking claims", e );
                return false;
            }
        }
        return true;
    }
    
    public static boolean checkPayloadValues( HttpServletRequest request, Key key, String strHeaderName, Map<String, String> claimsToCheck )
    {
        String strBase64JWT = request.getHeader( strHeaderName );

        // If no specific Header is provided, use spec JWT : try to fetch in Authorization: Bearer HTTP Header
        if ( strBase64JWT == null )
        {
            strBase64JWT = getAuthorizationBearerValue( request );
        }

        if ( strBase64JWT != null && !strBase64JWT.isEmpty( ) )
        {
            try
            {
                Claims claims = null;
                if (key instanceof SecretKey)
                {
                    claims = Jwts.parser( ).verifyWith( (SecretKey) key ).build( ).parseSignedClaims( strBase64JWT ).getPayload( );
                }
                else
                {
                    claims = Jwts.parser( ).verifyWith( (PublicKey) key ).build( ).parseSignedClaims( strBase64JWT ).getPayload( );
                }
                if ( null != claims )
                {
                    for ( Entry<String, String> entry : claimsToCheck.entrySet( ) )
                    {
                        if ( !claims.get( entry.getKey( ), String.class ).equals( entry.getValue( ) ) )
                        {
                            return false;
                        }
                    }
                }
            }
            catch( Exception e )
            {
                LOGGER.error( "Unable to get JWT Payload value", e );
                return false;
            }
        }
        return true;
    }
    
    /**
     * Check the JWT signature with provided java security Key: this can be a RSA Public Key
     * 
     * @param request
     *            The request
     * @param strHeaderName
     *            The header name
     * @param key
     *            The key
     * @return true if the signature of the JWT is checked; false otherwise
     */
    public static boolean checkSignature( HttpServletRequest request, String strHeaderName, Key key )
    {
        String strBase64JWT = request.getHeader( strHeaderName );

        // If no specific Header is provided, use spec JWT : try to fetch in Authorization: Bearer HTTP Header
        if ( strBase64JWT == null )
        {
            strBase64JWT = getAuthorizationBearerValue( request );
        }

        return checkSignature( strBase64JWT, key );
    }
    
    /**
     * Check the signature of the JWT with a secret key
     * 
     * @param mapClaims
     *              The map of claims
     * @param expirationDate
     *              The expiration date
     * @param strAlgo
     *              The algorythm name
     * @param key
     *              The key
     * @return true if the signature is checked, false otherwise
     */
    public static String buildBase64JWT( Map<String,String> mapClaims, Date expirationDate, String strAlgo, Key key )
    {
            JwtBuilder builder = Jwts.builder();
            
            builder.issuedAt( Date.from(Instant.now( ) ) );
            
            //Set claims
            for ( Entry<String,String> entry : mapClaims.entrySet( ) )
            {
                builder.claim( entry.getKey( ), entry.getValue( ) );
            }
            
            if ( expirationDate != null )
            {
                builder.expiration( expirationDate );
            }
            
            
            if ( key != null )
            {
                builder.signWith( key );
            }
                
            return builder.compact();
    }
    
    /**
     * Get a java security Key from a String secretKey and algorithm name
     * @param strSecretKey
     *              The secret Key
     * @param strAlgoName
     *              The algorithm name
     * @return The java securitySecretKey 
     */
    public static Key getKey( String strSecretKey, String strAlgoName )
    {
        try
        {
            Key key = new SecretKeySpec( strSecretKey.getBytes( "UTF-8"), strAlgoName );
            return Keys.hmacShaKeyFor( key.getEncoded( ) );
        }
        catch ( UnsupportedEncodingException e )
        {
        }
        return null;
    }

    /*
     * PRIVATE METHODS
     */
    /**
     * Get the Authorization Bearer value : "Authorization: Bearer XXXXXX" => exract XXXXX
     * 
     * @param request
     *            The request
     * @return the Authorization Bearer value in the request
     */
    private static String getAuthorizationBearerValue( HttpServletRequest request )
    {
        Enumeration<String> headers = request.getHeaders( "Authorization" );
        while ( headers.hasMoreElements( ) )
        {
            String value = headers.nextElement( );
            if ( value.toLowerCase( ).startsWith( "bearer" ) )
            {
                return value.substring( "bearer".length( ) ).trim( );
            }
        }
        return null;
    }

    /**
     * Check a JWT signature with a Java security Key
     * 
     * @param strBase64JWT
     * @param key
     * @return true if the JWT is checked, false otherwise
     */
    public static boolean checkSignature( String strBase64JWT, Key key )
    {
        try
        {
            if (key instanceof SecretKey)
            {
                Jwts.parser( ).verifyWith( (SecretKey) key ).build( ).parseSignedClaims( strBase64JWT ).getPayload( );
            }
            else 
            {
                Jwts.parser( ).verifyWith( (PublicKey) key ).build( ).parseSignedClaims( strBase64JWT ).getPayload( );
            }
        }

        catch( JwtException e )
        {
            return false;
        }
        return true;
    }

    /**
     * Removes signature and replaces header with an unsigned header (alg = none)
     * 
     * @param strBase64JWT
     * @return
     */
    private static String getUnsecuredBase64JWT( String strBase64JWT )
    {
        String s = strBase64JWT.split( "\\." )[1];
        return NO_SECURITY_ALG_HEADER + s + ".";
    }
    
}
