package com.businesslogic.security.proxy;

import com.businesslogic.security.models.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@Slf4j
public class AuthenticationServerProxy {
    @Autowired
    private RestTemplate rest;
    @Value("${auth.server.base.url}")
    private String baseUrl;

    public void sendAuth(String username, String password) {
        String url = baseUrl + "/user/auth";
        var body = new User();
        body.setUsername(username);
        body.setPassword(password);
        log.info("request sent to auth server {}", body);
        var request = new HttpEntity<>(body);
        log.info("url for request to auth server {}", url);
        rest.postForEntity(url, request, Void.class);
    }

    public boolean sendOTP(String username, String code) {
        String url = baseUrl + "/otp/check";
        var body = new User();
        body.setUsername(username);
        body.setCode(code);
        var request = new HttpEntity<>(body);
        var response = rest.postForEntity(url, request, Object.class);
        log.info("response from check api call {}",response);
        boolean equals = response.getStatusCode().equals(HttpStatus.OK);
        log.info("status code for calling endpoint {} is {}",url,response.getStatusCode());
        return equals;
    }
}
