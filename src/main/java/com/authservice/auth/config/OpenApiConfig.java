package com.authservice.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityRequirement;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {


@Bean
public OpenAPI authServiceAPI() {

    Server devServer = new Server();
    devServer.setUrl("http://localhost:8082");
    devServer.setDescription("Development Server");

    Server prodServer = new Server();
    prodServer.setUrl("https://api.yourdomain.com");
    prodServer.setDescription("Production Server");

    return new OpenAPI()

            .info(new Info()
                    .title("Auth Service API")
                    .version("1.0")
                    .description("JWT Authentication and Authorization Service"))

            .servers(List.of(devServer, prodServer))

            // JWT Security Scheme
            .components(new Components()
                    .addSecuritySchemes("bearerAuth",
                            new SecurityScheme()
                                    .type(SecurityScheme.Type.HTTP)
                                    .scheme("bearer")
                                    .bearerFormat("JWT")
                                    .description("JWT Authorization header using Bearer scheme")))

            // Global Security
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
}


}
