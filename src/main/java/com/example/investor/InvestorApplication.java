package com.example.investor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class InvestorApplication {
    public static void main(String[] args) { SpringApplication.run(InvestorApplication.class, args); }
}
