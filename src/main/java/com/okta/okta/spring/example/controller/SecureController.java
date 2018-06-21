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

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class SecureController {

    public static final String AUTHENTICATED_PATH = "/authenticated";

    @RequestMapping(AUTHENTICATED_PATH)
    @PreAuthorize("#oauth2.hasScope('openid')")
    public String authenticated() {
        return "authenticated";
    }

    @RequestMapping("/users")
    @PreAuthorize("hasAuthority('users')")
    public String users() {
        return "roles";
    }

    @RequestMapping("/admins")
    @PreAuthorize("hasAuthority('admins')")
    public String admins() {
        return "roles";
    }

    @RequestMapping("/403")
    public String error403() {
        return "403";
    }
}
