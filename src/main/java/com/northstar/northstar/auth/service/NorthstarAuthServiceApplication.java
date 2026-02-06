package com.northstar.northstar.auth.service;

import com.northstar.northstar.auth.service.configuration.AppConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(value = AppConfiguration.class)
public class NorthstarAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(NorthstarAuthServiceApplication.class, args);
    }
}
