package net.prosetyle.springsecuritydemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private String parameterName = "_csrf";
    private String headerName = "X-XSRF-TOKEN";

    @PostMapping("/login")
    public String getLoginPage() {
        return "login";
    }

    @GetMapping("/success")
    public String geSuccessPage() {
        return "success";
    }

}
