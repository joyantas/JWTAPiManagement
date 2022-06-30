// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.azure.spring.sample.aad.controller;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.azure.spring.cloud.autoconfigure.aad.filter.UserPrincipal;

@RestController
public class MainController {

    @GetMapping("/public")
    @ResponseBody
    public String publicMethod() {
        return "public endpoint response";
    }

    @RequestMapping("/authorized")
    @ResponseBody
    // @PreAuthorize("hasRole('ROLE_UserRule')")
    public String onlyAuthorizedUsers(PreAuthenticatedAuthenticationToken authToken) {
        final UserPrincipal current = (UserPrincipal) authToken.getPrincipal();
        Map<String, Object> prince = current.getClaims();
        String sRet = "Application Token only";

        if (current.getClaim("name") == null)
            sRet += " with Audience:  " + current.getClaim("aud");
        else
            sRet = (String) current.getClaim("name");

        return "authorized endpoint response Hello: " + sRet;
    }

    @GetMapping("/admin/demo")
    @ResponseBody
    // For demo purposes for this endpoint we configure the required role in the
    // AadWebSecurityConfig class.
    // However, it is advisable to use method level security with
    // @PreAuthorize("hasRole('xxx')")
    public String onlyForAdmins() {
        return "admin endpoint";
    }
}
