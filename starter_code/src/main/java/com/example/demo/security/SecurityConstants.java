package com.example.demo.security;

public class SecurityConstants {

    public static final long EXPIRATION_TIME = 604_800_000;
    public static final String HEADER_STRING = "Authorization";
    public static final String SECRET = "KeyToGenerateJWTs";
    public static final String SIGN_UP_URL = "/api/user/create";
    public static final String TOKEN_PREFIX = "Bearer ";
}
