package com.smartorders.userservice.user_service.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("User Service API")
                        .version("1.0.0")
                        .description("API for managing users in the Smart Orders application")
                        .contact(new Contact()
                                .name("Smart Orders Team")
                                .email("tairovich.solutions@gmail.com")
                                .url("https://smartorders.com/contact")));

    }
}