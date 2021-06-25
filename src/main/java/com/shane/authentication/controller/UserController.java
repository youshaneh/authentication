package com.shane.authentication.controller;

import com.shane.authentication.entity.user.AuthType;
import com.shane.authentication.entity.user.UserRequest;
import com.shane.authentication.entity.user.UserResponse;
import com.shane.authentication.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping(value = "/users", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController {
    @Autowired
    UserService service;

    @GetMapping("/{id}")
    public UserResponse getUser(@PathVariable("id") Long id){
        return service.getUser(id);
    }

    @PostMapping
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody UserRequest request){
        UserResponse user = service.createUser(request.getName(), request.getEmail(), request.getPassword(), AuthType.SITE);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(user.getId())
                .toUri();

        return ResponseEntity.created(location).body(user);
    }

    @PatchMapping("/{id}")
    public UserResponse updateUser(@PathVariable("id") Long id, @RequestBody(required = false) UserRequest request){
        return service.updateUser(id, request);
    }
}
