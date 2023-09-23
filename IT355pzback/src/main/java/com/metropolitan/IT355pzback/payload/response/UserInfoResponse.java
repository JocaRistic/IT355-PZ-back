package com.metropolitan.IT355pzback.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class UserInfoResponse {
    private int id;
    private String ime;
    private String prezime;
    private String username;
    private String email;
    private List<String> roles;
}
