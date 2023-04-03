package com.businesslogic.security.filters;

import com.businesslogic.security.providers.OtpAuthentication;
import com.businesslogic.security.providers.UsernamePasswordAuthentication;
import com.businesslogic.security.utils.JwtTokenUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Key;
import java.util.Map;

@Component
@Slf4j
public class InitialAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    JwtTokenUtil jwtTokenUtil;
    @Autowired
    private AuthenticationManager manager;
    @Value("${jwt.signing.key}")
    private String signingKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {


        byte[] body = StreamUtils.copyToByteArray(request.getInputStream());

        Map jsonRequest = new ObjectMapper().readValue(body, Map.class);

        System.out.println(jsonRequest);
        System.out.println("data re ke " + request.getParameter("username"));
        System.out.println("text re ke " + request.getParameter("text"));


        String username = request.getHeader("username");
        String password = request.getHeader("password");
        String code = request.getHeader("code");
//        log.info("here is the request attributes {}",request.getAttributeNames().toString());
//        log.info("here is the request reader {}", request);
//        log.info("here is the request getParameter {}",request.getParameter("data"));
//        String text = new BufferedReader(
//                new InputStreamReader(request.getInputStream(), StandardCharsets.UTF_8))
//                .lines()
//                .collect(Collectors.joining("\n"));
//        System.out.println(text);
//        request.getAttributeNames().asIterator().forEachRemaining(e->log.info("here is body {}",e));
//        log.info("here is the request getParameterMap names {}",request.getParameterMap().toString());
        if (code == null) {
            Authentication a =
                    new UsernamePasswordAuthentication(username, password);
            manager.authenticate(a);
        } else {
            Authentication a =
                    new OtpAuthentication(username, code);
            manager.authenticate(a);

            String jws = jwtTokenUtil.doGenerateToken(Map.of("username", username));
            response.setHeader("Authorization", jws);
        }
    }

    @Override
    protected boolean shouldNotFilter(
            HttpServletRequest request) {
        return !request.getServletPath()
                .equals("/login");
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(this.signingKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
