package com.okta.okta.spring.example.controller;

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

import com.okta.spring.config.OktaClientProperties;
import com.okta.spring.config.OktaOAuth2Properties;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@Controller
public class HomeController {

    private final OktaOAuth2Properties oktaOAuth2Properties;
    private final OktaClientProperties oktaClientProperties;

    public HomeController(OktaOAuth2Properties oktaOAuth2Properties, OktaClientProperties oktaClientProperties) {
        this.oktaOAuth2Properties = oktaOAuth2Properties;
        this.oktaClientProperties = oktaClientProperties;
    }

    @RequestMapping("/")
    public String home(Principal principal) {
        if (principal != null) {
            return "redirect:" + SecureController.AUTHENTICATED_PATH;
        }
        return "home";
    }

    @RequestMapping("/login")
    public String login(
        Model model,
        HttpServletRequest request,
        @RequestParam(name = "state", required = false) String springState
    ) {
        if (springState == null) {
            return "redirect:" + oktaOAuth2Properties.getRedirectUri();
        }
        model.addAttribute("state", springState);
        model.addAttribute("redirectUri",
            request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() +
            request.getContextPath() + oktaOAuth2Properties.getRedirectUri()
        );
        model.addAttribute("clientId", oktaOAuth2Properties.getClientId());
        model.addAttribute("issuer", oktaOAuth2Properties.getIssuer());
        model.addAttribute("scopes", oktaOAuth2Properties.getScopes());
        model.addAttribute("baseUrl", oktaClientProperties.getOrgUrl());
        return "login";
    }
}
