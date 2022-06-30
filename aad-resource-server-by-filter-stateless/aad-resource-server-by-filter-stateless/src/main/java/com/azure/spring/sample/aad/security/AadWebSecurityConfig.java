// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.azure.spring.sample.aad.security;

import com.azure.spring.cloud.autoconfigure.aad.filter.AadAppRoleStatelessAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AadWebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AadAppRoleStatelessAuthenticationFilter aadAuthFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        // Main a session eg. JSESSION which will keep the context so no graph call will
        // be made after a suscessful login with the Token.
        // you will see the generated Cookie JSESSIONID eg. in Postman.
        // eg is set SessionCreationPolicy.NEVER it might create a session
        // use SessionCreationPolicy.STATELESS to make sure each request gets
        // authenticated.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("Admin")
                .antMatchers("/", "/index.html", "/public").permitAll()
                .anyRequest().authenticated();

        http.addFilterBefore(aadAuthFilter, UsernamePasswordAuthenticationFilter.class);

    }
}
