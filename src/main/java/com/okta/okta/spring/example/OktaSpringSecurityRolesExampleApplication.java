package com.okta.okta.spring.example;

/*
Copyright 2018 Okta, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


import com.okta.okta.spring.example.controller.CustomAccessDeniedHandler;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@SpringBootApplication
public class OktaSpringSecurityRolesExampleApplication {

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    static class OAuth2SecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        private final CustomAccessDeniedHandler customAccessDeniedHandler;

        OAuth2SecurityConfigurerAdapter(CustomAccessDeniedHandler customAccessDeniedHandler) {
            this.customAccessDeniedHandler = customAccessDeniedHandler;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .exceptionHandling()
                    .accessDeniedHandler(customAccessDeniedHandler)
                .and()
                    .authorizeRequests()
                    .antMatchers("/", "/login", "/images/**", "/favicon.ico")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                .and()
                    .logout()
                    .logoutSuccessUrl("/");
        }
    }

    public static void main(String[] args) {
		SpringApplication.run(OktaSpringSecurityRolesExampleApplication.class, args);
	}
}
