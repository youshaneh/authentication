package com.shane.authentication.service;

import com.shane.authentication.entity.user.AuthType;
import com.shane.authentication.entity.user.User;
import com.shane.authentication.entity.user.UserRequest;
import com.shane.authentication.entity.user.UserResponse;
import com.shane.authentication.exception.ConflictException;
import com.shane.authentication.exception.NotFoundException;
import com.shane.authentication.exception.UnprocessableEntityException;
import com.shane.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.apache.commons.validator.routines.EmailValidator;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.Optional;

import static com.shane.authentication.service.AuthService.USER_ID;

@Service
public class UserService {
    @Autowired
    UserRepository repository;

    EmailValidator validator = EmailValidator.getInstance();
    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public UserResponse getUser(long id){
        long loggedInUserId = (long) SecurityContextHolder.getContext().getAuthentication().getDetails();
        if(id != loggedInUserId) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "The logged in user doesn't match the queried one");
        }
        User user = repository.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return new UserResponse(user.getId(), user.getName(), user.getEmail(), user.getAuthType());
    }

    public UserResponse createUser(String name, String email, String password, AuthType authType){
        Optional<User> existingUser = repository.findByEmailAndAuthType(email, authType.getId());
        if (existingUser.isPresent()) throw new ConflictException("This email address is in use.");
        if (!validator.isValid(email)) throw new UnprocessableEntityException("This email address is malformed.");

        User user = new User();
        user.setName(name);
        user.setEmail(email);
        if(AuthType.SITE.equals(authType)) user.setPassword(passwordEncoder.encode(password));
        user.setAuthType(authType);
        user = repository.save(user);
        return new UserResponse(user.getId(), user.getName(), user.getEmail(), user.getAuthType());
    }

    public UserResponse updateUser(long id, UserRequest request){
        long loggedInUserId = (long) SecurityContextHolder.getContext().getAuthentication().getDetails();
        if(id != loggedInUserId) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "The logged in user doesn't match the one queried");
        }
        User user = repository.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        if(request.getName() != null) user.setName(request.getName());
        if(request.getEmail() != null) user.setEmail(request.getEmail());
        if(request.getPassword() != null && request.getPassword().length() > 0 && AuthType.SITE.equals(user.getAuthType())) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }
        user = repository.save(user);
        return new UserResponse(user.getId(), user.getName(), user.getEmail(), user.getAuthType());
    }

    public Optional<User> getUserByEmailAndAuthType(String email, AuthType authType) {
        return repository.findByEmailAndAuthType(email, authType.getId());
    }
}
