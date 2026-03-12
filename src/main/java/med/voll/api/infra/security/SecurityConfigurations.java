package med.voll.api.infra.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfigurations {

    private final SecurityFilter securityFilter;

    @Bean
    public SecurityFilterChain securityFilterChainBean(HttpSecurity http) throws Exception {
        // desabilita o tratamento de CSRF (Cross-Site Request Forgery ou Falsificação de Solicitação entre Sitespois o proprio JWT ja trata isso
        // caso contrario o spring security por padrão vai bloquear todas as reqs sem login e senha
        return http.csrf().disable()
                // desabilitando processo de autenticação por formulário (stateful) e ativando autenticação stateless
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().authorizeHttpRequests() // esta linha e abaixo responsaveis por dizer ao spring para só liberear
                .antMatchers(HttpMethod.POST, "/login").permitAll() // requisições POST para /login. as outras ficam bloqueadas
                // .requestMatchers(HttpMethod.DELETE, "/medicos").hasRole("ADMIN")
                // .requestMatchers(HttpMethod.DELETE, "/pacientes").hasRole("ADMIN")
                .anyRequest().authenticated() // para qualquer outra req, é necessario estar autenticado
                .and().addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class) // diz ao spring para chamas o nosso filtro antes do dele. pois é no nosso que será definido que o usuario esta logado
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
