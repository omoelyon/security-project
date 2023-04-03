package com.businesslogic.security.filters;

import com.businesslogic.security.providers.UsernamePasswordAuthentication;
import com.businesslogic.security.utils.JwtTokenUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Key;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Value("${jwt.signing.key}")
    private String signingKey;
    @Autowired
    JwtTokenUtil jwtTokenUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        String jwt = request.getHeader("Authorization");
        Map claims = new HashMap<>();

        try {
            claims = jwtTokenUtil.getDetailsFromToken(jwt);

        } catch (JwtException e) {
            e.printStackTrace();
        }

        String username = String.valueOf(claims.get("subject"));
        GrantedAuthority a = new SimpleGrantedAuthority("user");
        var auth = new UsernamePasswordAuthentication(
                username,
                null,
                List.of(a));
        SecurityContextHolder.getContext()
                .setAuthentication(auth);
        log.info("here are the claims {}",claims);
        filterChain.doFilter(request, response);

    }

    @Override
    protected boolean shouldNotFilter(
            HttpServletRequest request) {
        return request.getServletPath()
                .equals("/login");
    }
}
