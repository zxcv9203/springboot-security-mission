package com.programmers.devcourse.config;

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

import java.util.logging.Filter;

public class CustomWebSecurityExpressionHandler extends AbstractSecurityExpressionHandler<FilterInvocation> {

    private final AuthenticationTrustResolver trustResolver;
    private final String defaultRolePrefix;

    public CustomWebSecurityExpressionHandler(AuthenticationTrustResolver trustResolver, String defaultRolePrefix) {
        this.trustResolver = trustResolver;
        this.defaultRolePrefix = defaultRolePrefix;
    }

    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
                                                                        FilterInvocation fi) {
        CustomWebSecurityExpressionRoot root = new CustomWebSecurityExpressionRoot(authentication, fi);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(this.trustResolver);
        root.setRoleHierarchy(getRoleHierarchy());
        root.setDefaultRolePrefix(this.defaultRolePrefix);
        return root;
    }
}
