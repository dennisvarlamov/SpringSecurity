package net.prosetyle.springsecuritydemo.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.UUID;

public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private String parameterName = "_csrf";
    private String headerName = "X-XSRF-TOKEN";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        HttpSession session = request.getSession(true);
        DefaultCsrfToken defaultCsrfToken = new DefaultCsrfToken(this.headerName, this.parameterName, this.createNewToken());
        session.setAttribute("token", defaultCsrfToken);
        response.getWriter().write(defaultCsrfToken.getToken());
    }

    private String createNewToken() { return UUID.randomUUID().toString(); }
}