package com.shane.authentication.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:3000", "https://iredeem.tk")
                .allowedMethods("GET", "POST", "DELETE", "PUT", "PATCH")
                .allowedHeaders("Content-Type", "Authorization")
                .maxAge(24 * 60 * 60);
    }
}