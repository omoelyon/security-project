package com.businesslogic.security.models;

import lombok.Data;

@Data
public class User {
    private String username;
    private String password;
    private String code;
}
