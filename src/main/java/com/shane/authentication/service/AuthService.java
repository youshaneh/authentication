package com.shane.authentication.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.shane.authentication.config.SecurityConfig;
import com.shane.authentication.entity.auth.AuthRequest;
import com.shane.authentication.entity.auth.GoogleOAuthTokenResponse;
import com.shane.authentication.entity.user.AuthType;
import com.shane.authentication.entity.user.User;
import com.shane.authentication.entity.user.UserResponse;
import com.shane.authentication.exception.NotFoundException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.SneakyThrows;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.ResponseBody;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class AuthService {
    final static public String USER_ID = "userId";

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private SecurityConfig securityConfig;

    public String authenticate(AuthRequest request) {
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
        authentication = authenticationManager.authenticate(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userService.getUserByEmailAndAuthType(userDetails.getUsername(), AuthType.SITE)
                .orElseThrow(() -> new NotFoundException("Can't find any user from this email."));
        return createToken(user.getId());
    }

    @SneakyThrows
    public String googleOAuth(String code) {
        OkHttpClient client = new OkHttpClient();

        FormBody requestBody = new FormBody.Builder()
                .addEncoded("code", java.net.URLDecoder.decode(code, StandardCharsets.UTF_8.name()))
                .addEncoded("client_id", securityConfig.getOauthGoogleClientId())
                .addEncoded("client_secret", securityConfig.getOauthGoogleClientSecret())
                .addEncoded("redirect_uri", securityConfig.getOauthGoogleRedirectUri())
                .addEncoded("grant_type", "authorization_code")
                .build();
        Request request = new Request.Builder()
                .url("https://oauth2.googleapis.com/token")
                .post(requestBody)
                .build();
        ObjectMapper objectMapper = new ObjectMapper();
        ResponseBody responseBody = client.newCall(request).execute().body();
        GoogleOAuthTokenResponse response = objectMapper.readValue(responseBody.string(), GoogleOAuthTokenResponse.class);

        request = new Request.Builder()
                .url("https://www.googleapis.com/oauth2/v1/userinfo")
                .header("Authorization", "Bearer " + response.getAccessToken())
                .build();
        String result = client.newCall(request).execute().body().string();
        JsonNode jsonResult = objectMapper.readTree(result);
        //jsonResult.get("email").asText(), jsonResult.get("given_name").asText()

        Optional<User> user = userService.getUserByEmailAndAuthType(jsonResult.get("email").asText(), AuthType.GOOGLE);
        long userId;
        if(user.isPresent()) {
            userId = user.get().getId();
        }
        else{
            UserResponse createdUser = userService.createUser(jsonResult.get("given_name").asText(), jsonResult.get("email").asText(), null, AuthType.GOOGLE);
            userId = createdUser.getId();
        }
        return createToken(userId);
    }

    public String createToken(long userId){
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, 100);

        Claims claims = Jwts.claims();
        claims.setIssuer("iRedeem");
        claims.setExpiration(calendar.getTime());
        claims.put(USER_ID, userId);

        return Jwts.builder()
                .setClaims(claims)
                .signWith(getPrivateKey(securityConfig.getJwtPrivateKey()), SignatureAlgorithm.RS256)
                .compact();
    }

    public Map<String, Object> parseToken(String token) {
        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(getPublicKey(securityConfig.getJwtPublicKey()))
                .build();

        Claims claims = parser
                .parseClaimsJws(token)
                .getBody();

        return claims.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @SneakyThrows
    private PublicKey getPublicKey(String key) {
        byte[] byteKey = Base64.getDecoder().decode(key);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(byteKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    @SneakyThrows
    private PrivateKey getPrivateKey(String key) {
        byte[] byteKey = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(byteKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }
}
