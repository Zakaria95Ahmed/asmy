package com.bdt.asmy.Utility;

import com.bdt.asmy.Model.UserData;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static java.util.Arrays.stream;

@Component
@Slf4j
public class JWTProvider {

    @Value("${jwt.ZAG_ZAG}")
    private String JWT_Secret;

    public String generateJwtToken(UserData userPrincipal) {
        String testAsaad;
        String[] claims = getClaimsFromUser(userPrincipal);
        log.info("secret2=" + JWT_Secret);
        System.out.println("secret=" + JWT_Secret);
        testAsaad = JWT.create()
                .withIssuer("ZAG_ZAG-Company")
                .withAudience("Zakaria Ahmed")
                .withIssuedAt(new Date())
                .withSubject(userPrincipal.getUsername())
                .withArrayClaim("AUTHORITIES Zakaria Ahmed", claims)
                .withExpiresAt(new Date(System.currentTimeMillis() + 259_200_000))//// 3*24*60*60*1000=259_200_000 3 days expressed in milliseconds
                .sign(HMAC512(JWT_Secret.getBytes()));
        System.out.println("secret2=" + JWT_Secret);
        log.info("secret2=" + JWT_Secret);
        System.out.println(testAsaad);
        return testAsaad;

    }

    public List<GrantedAuthority> getAuthorities(String token) {
        String[] claims = getClaimsFromToken(token);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    public Authentication getAuthentication(String username, List<GrantedAuthority> authorities, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken userPasswordAuthToken = new
                UsernamePasswordAuthenticationToken(username, null, authorities);
        userPasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return userPasswordAuthToken;
    }

    public boolean isTokenValid(String username, String token) {
        JWTVerifier verifier = getJWTVerifier();
        return StringUtils.isNotEmpty(username) && !isTokenExpired(verifier, token);
    }

    public String getSubject(String token) {
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getSubject();
    }

    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expiration = verifier.verify(token).getExpiresAt();
        return expiration.before(new Date());
    }

    private String[] getClaimsFromToken(String token) {
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getClaim("AUTHORITIES Zakaria Ahmed").asArray(String.class);
    }

    private JWTVerifier getJWTVerifier() {
        JWTVerifier verifier;
        try {
            Algorithm algorithm = HMAC512(JWT_Secret);
            verifier = JWT.require(algorithm).withIssuer("ZAG_ZAG-Company").build();
        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException("Token cannot be verified");
        }
        return verifier;
    }

    private String[] getClaimsFromUser(UserData user) {
        List<String> authorities = new ArrayList<>();
        for (GrantedAuthority grantedAuthority : user.getAuthorities()) {
            authorities.add(grantedAuthority.getAuthority());
        }
        return authorities.toArray(new String[0]);
    }
}
