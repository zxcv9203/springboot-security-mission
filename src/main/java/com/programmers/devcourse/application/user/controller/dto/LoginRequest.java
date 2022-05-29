package com.programmers.devcourse.application.user.controller.dto;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

public class LoginRequest {

    private String principal;

    private String credential;

    protected LoginRequest() {}

    public LoginRequest(String principal, String credentials) {
        this.principal = principal;
        this.credential = credentials;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getCredential() {
        return credential;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("principal", principal)
                .append("credential", credential)
                .toString();
    }

}
