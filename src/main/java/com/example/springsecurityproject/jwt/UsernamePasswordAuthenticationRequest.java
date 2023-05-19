package com.example.springsecurityproject.jwt;

public class UsernamePasswordAuthenticationRequest {
    private String userName;
    private String password;

    public UsernamePasswordAuthenticationRequest() {
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
