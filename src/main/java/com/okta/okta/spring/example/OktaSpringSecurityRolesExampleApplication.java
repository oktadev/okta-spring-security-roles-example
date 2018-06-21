package com.okta.okta.spring.example;

/*
Copyright 2017 Okta, Inc.

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
import com.okta.spring.config.OktaOAuth2Properties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.Filter;

@SpringBootApplication
@EnableOAuth2Sso
public class OktaSpringSecurityRolesExampleApplication {

    private final OktaOAuth2Properties oktaOAuth2Properties;

    public OktaSpringSecurityRolesExampleApplication(CustomAccessDeniedHandler customAccessDeniedHandler, OktaOAuth2Properties oktaOAuth2Properties) {
        this.oktaOAuth2Properties = oktaOAuth2Properties;
    }

    @EnableGlobalMethodSecurity(prePostEnabled = true)
    protected static class GlobalSecurityConfiguration extends GlobalMethodSecurityConfiguration {
        @Override
        protected MethodSecurityExpressionHandler createExpressionHandler() {
            return new OAuth2MethodSecurityExpressionHandler();
        }
    }

    @Bean
    protected Filter oktaSsoFilter(
        ApplicationEventPublisher applicationEventPublisher,
        OAuth2ClientContext oauth2ClientContext,
        AuthorizationCodeResourceDetails authorizationCodeResourceDetails,
        ResourceServerTokenServices tokenServices
    ) {
        OAuth2ClientAuthenticationProcessingFilter oktaFilter = new OAuth2ClientAuthenticationProcessingFilter(oktaOAuth2Properties.getRedirectUri());
        oktaFilter.setApplicationEventPublisher(applicationEventPublisher);
        OAuth2RestTemplate oktaTemplate = new OAuth2RestTemplate(authorizationCodeResourceDetails, oauth2ClientContext);
        oktaFilter.setRestTemplate(oktaTemplate);
        oktaFilter.setTokenServices(tokenServices);
        return oktaFilter;
    }

    @Configuration
    @Order(99)
    static class OAuth2SecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        private final Filter oktaSsoFilter;
        private final OktaOAuth2Properties oktaOAuth2Properties;
        private final CustomAccessDeniedHandler customAccessDeniedHandler;

        OAuth2SecurityConfigurerAdapter(
            Filter oktaSsoFilter, OktaOAuth2Properties oktaOAuth2Properties,
            CustomAccessDeniedHandler customAccessDeniedHandler
        ) {
            this.oktaSsoFilter = oktaSsoFilter;
            this.oktaOAuth2Properties = oktaOAuth2Properties;
            this.customAccessDeniedHandler = customAccessDeniedHandler;
        }

        @Bean
        protected AuthenticationEntryPoint authenticationEntryPoint() {
            return new LoginUrlAuthenticationEntryPoint(oktaOAuth2Properties.getRedirectUri());
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .addFilterAfter(oktaSsoFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling()
                    .authenticationEntryPoint(authenticationEntryPoint())
                    .accessDeniedHandler(customAccessDeniedHandler)
                .and()
                    .authorizeRequests()
                    .antMatchers("/", "/login", "/images/**", "/favicon.ico").permitAll()
                .and()
                    .logout()
                    .logoutSuccessUrl("/");
        }
    }

    public static void main(String[] args) {
		SpringApplication.run(OktaSpringSecurityRolesExampleApplication.class, args);
	}
}
