package com.studing.allmonster.payload.response;

import org.springframework.stereotype.Component;

import java.util.List;
public class JwtResponse {
    private String token;

    private String username;
    private String name;


    public JwtResponse(String accessToken,
                       String username,
                       String name

    ) {
        this.token = accessToken;
        this.username = username;
        this.name = name;
    }

    public String getAccessToken() {
        return token;
    }

    public void setAccessToken(String accessToken) {
        this.token = accessToken;
    }


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

}