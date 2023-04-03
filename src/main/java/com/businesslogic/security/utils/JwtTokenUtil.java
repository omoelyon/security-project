package com.businesslogic.security.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static io.jsonwebtoken.security.Keys.secretKeyFor;


@Component
@Slf4j
public class JwtTokenUtil {
    @Value("${jwt.signing.key}")
    private String jwtSecret;
    //    @Value("${security.jwt.token.expire:3600000}")
    private final long validityInMilliseconds = 3600000;
    private final long refreshValidityInMilliseconds = 259200000;
    private long termiiId;


    public String generateToken(Map<String, Object> claims) throws UnsupportedEncodingException {
//        Map<String, Object> claims = new HashMap<>();
//        claims.put(CLAIM_KEY_SUB, subject.getUserId());
//        claims.put(CLAIM_KEY_EMAIL, subject.getEmail());
//        claims.put(CLAIM_KEY_CREATED, subject.getTokenCreation());
//        claims.put(CLAIM_KEY_GRANT, subject.getAuthorities());
//        claims.put(CLAIM_KEY_COMPANY, subject.getCompanyId());
//        claims.put(CLAIM_KEY_ADMIN, subject.getAdminId());
//        claims.put(CLAIM_KEY_APP, subject.getApplicationId());
//        claims.put(CLAIM_KEY_COUNTRY, subject.getCountry());
        return doGenerateToken(claims);
    }

    public String doGenerateToken(Map<String, Object> claims) throws UnsupportedEncodingException {
        Key key = secretKeyFor(SignatureAlgorithm.HS256);

        String jwtIssuer = "adeola.com";
        String jwt = Jwts.builder().setClaims(claims).setIssuer(jwtIssuer).setSubject("subject").setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, getJwtSecret()).compact();
        log.info("jwt string {}", jwt);
        return jwt;
    }

    private byte[] getJwtSecret() throws UnsupportedEncodingException {
        byte[] secretKeyByteArray = new byte[256];
        System.arraycopy(jwtSecret.getBytes(), 0, secretKeyByteArray, 256 - jwtSecret.length(), jwtSecret.length());
        log.info("size of byte array is {} and array itself is {}", secretKeyByteArray.length,secretKeyByteArray);
        return secretKeyByteArray;
    }


    public Map<String, Object> getDetailsFromToken(String token) {
        try {
            final Claims claims = getClaimsFromToken(token);
            return claims;
        } catch (Exception e) {
            log.debug("Method: getUsernameFromToken({})[{}]", token, e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public Map<String, Object> getDetailsFromTokenStatic(String token) {
        try {
            Map<String, Object> expectedMap = new HashMap<>(getClaimsFromToken(token));

//            Long userId = Long.valueOf(claims.getSubject());
//            Long companyId = Long.valueOf(claims.getIssuer());
//            String authorities = (String) claims.get(CLAIM_KEY_GRANT);
//            Long applicationId = Long.valueOf((Integer) claims.get(CLAIM_KEY_APP));
//            JwtSubject subject = new JwtSubject(userId, applicationId, companyId, authorities);
//            subject.setTokenCreation((Long) claims.get(CLAIM_KEY_CREATED));
            return expectedMap;
        } catch (Exception e) {
            log.debug("Method: getUsernameFromToken({})[{}]", token, e.getMessage());
            e.printStackTrace();
            return null;
        }
    }


    private Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(getJwtSecret()).parseClaimsJws(token).getBody();
            log.info("clames {}", claims);
        } catch (Exception e) {
            log.debug("getClaimsFromToken : " + e.getMessage());
//            e.printStackTrace();
            claims = null;
        }
        return claims;
    }
//    public Boolean validateToken(String token, UserDetails userDetails) {
//        final String username = extractUsername(token);
//        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
//    }

}
