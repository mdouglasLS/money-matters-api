package com.daroz.money_matters_api.config.security;

import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.apache.catalina.util.ParameterMap;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RefreshTokenCookiePreProcessor implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        if ("/api/v1/auth/refresh-token".equalsIgnoreCase(req.getRequestURI()) && req.getCookies() != null) {
            for (Cookie cookie: req.getCookies()) {
                if (cookie.getName().equalsIgnoreCase("refreshToken")){
                    String refreshToken = cookie.getValue();
                    req = new MyServletRequestWrapper(req, refreshToken);
                }
            }
        }

        chain.doFilter(req, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }

    static class MyServletRequestWrapper extends HttpServletRequestWrapper {

        private final String refreshToken;

        public MyServletRequestWrapper(HttpServletRequest request, String refreshToken) {
            super(request);
            this.refreshToken = refreshToken;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            ParameterMap<String, String[]> map = new ParameterMap<>(getRequest().getParameterMap());
            map.put("refreshToken", new String[]{ refreshToken });
            map.setLocked(true);
            return map;
        }
    }

}
