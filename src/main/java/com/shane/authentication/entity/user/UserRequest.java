package com.shane.authentication.entity.user;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.Size;

@Data
public class UserRequest {
    @Email(message = "Email should be valid")
    private String email;

    @Size(min = 6, max = 32, message = "Password must be between 6 and 32 characters")
    private String password;

    @Size(min = 1, max = 128, message = "Name must be between 1 and 48 characters")
    private String name;
}
