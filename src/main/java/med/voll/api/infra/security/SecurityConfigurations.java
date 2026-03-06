package med.voll.api.infra.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfigurations {

    @Bean
    public SecurityFilterChain securityFilterChainBean(HttpSecurity http) throws Exception {
        // desabilita o tratamento de CSRF (Cross-Site Request Forgery ou Falsificação de Solicitação entre Sitespois o proprio JWT ja trata isso
        // caso contrario o spring security por padrão vai bloquear todas as reqs sem login e senha
        return http.csrf(csrf -> csrf.disable())
                // desabilitando processo de autenticação por formulário (stateful) e ativando autenticação stateless
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

    // cria a instancia para ser possivel realizar a injeção de dependencia do AuthenticationManager
    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // informar ao spring qual a critpografia usada nas senhas
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
