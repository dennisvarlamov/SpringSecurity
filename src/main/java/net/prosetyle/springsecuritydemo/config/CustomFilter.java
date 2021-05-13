package net.prosetyle.springsecuritydemo.config;

import lombok.SneakyThrows;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

public class CustomFilter extends UsernamePasswordAuthenticationFilter {

    private String parameterName = "_csrf";
    private String headerName = "X-XSRF-TOKEN";

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken("admin", "admin");

        setDetails(request, authRequest);

        return super.getAuthenticationManager().authenticate(authRequest);
    }

    private String createNewToken() { return UUID.randomUUID().toString(); }
}
