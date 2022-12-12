package com.example.payload;

public class LoginResponse {
    public final String accessToken;
    public final String tokenType = "Bearer";

    public LoginResponse(String accessToken) {
        this.accessToken = accessToken;
    }
}