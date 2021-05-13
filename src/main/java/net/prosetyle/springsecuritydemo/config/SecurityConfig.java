package net.prosetyle.springsecuritydemo.config;

import net.prosetyle.springsecuritydemo.model.Permission;
import net.prosetyle.springsecuritydemo.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
// второй тип авторизации добавить
// подцепить реалихации realm(почитать)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers(HttpMethod.GET ,"/api/**").hasAuthority(Permission.DEVELOPERS_READ.getPermission())
//                .antMatchers(HttpMethod.POST ,"/api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermisson())
//                .antMatchers(HttpMethod.DELETE ,"/api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermisson())
                .anyRequest()
                .authenticated()
                .and()
//                .formLogin()
//                .loginPage("/auth/login").permitAll()
//                .defaultSuccessUrl("/auth/success")
//                .and()
//                .logout()
//                .logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST"))
//                .invalidateHttpSession(true)
//                .clearAuthentication(true)
//                .deleteCookies("JSESSIONID")
//                .logoutSuccessUrl("/auth/login");
                .httpBasic()
                .and()
                .addFilterBefore(customFilter(), UsernamePasswordAuthenticationFilter.class)
                .csrf()
                    .ignoringAntMatchers("/auth/auth")
                //.disable()
                .csrfTokenRepository(csrfTokenRepository())
                ;
    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("admin"))
                        .authorities(Role.ADMIN.getAuthorities())
                        .build(),
                User.builder()
                        .username("user")
                        .password(passwordEncoder().encode("user"))
                        .authorities(Role.USER.getAuthorities())
                        .build()
        );
    }

    @Bean
    protected PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler();
    }

    @Bean
    public CustomFilter customFilter() throws Exception {
        CustomFilter customFilter = new CustomFilter();
        customFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/auth/auth", "POST"));
        customFilter.setAuthenticationManager(authenticationManagerBean());
        customFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());

        return customFilter;
    }

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        return new CsrfTokenSessionRepository();
    }
}