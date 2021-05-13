package net.prosetyle.springsecuritydemo.config;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.UUID;


public class CsrfTokenSessionRepository implements CsrfTokenRepository {
    private String parameterName = "_csrf";
    private String headerName = "X-XSRF-TOKEN";


    @Override
    public CsrfToken generateToken(HttpServletRequest httpServletRequest) {
        return new DefaultCsrfToken(this.headerName, this.parameterName, this.createNewToken());
    }

    @Override
    public void saveToken(CsrfToken csrfToken, HttpServletRequest request, HttpServletResponse response) {
//        try {
//            response.getWriter().write(csrfToken.getToken());
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
//        String csrfToken = request.getHeader(this.headerName);
//        if (csrfToken == null) {
//            return null;
//        }
//        return !StringUtils.hasLength(csrfToken) ? null : new DefaultCsrfToken(this.headerName, this.parameterName, csrfToken);
        HttpSession session = request.getSession(false);
        return session == null ? null : (CsrfToken)session.getAttribute("token");
    }

    private String createNewToken() {
        return UUID.randomUUID().toString();
    }
}
