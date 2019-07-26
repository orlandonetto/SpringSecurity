package com.example.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity //Habilita o módulo de segurança na aplicação
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired // classe service que tem a lógica de autenticação.
    private AuthenticationService authService;

    @Override //Configurações de autenticação
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // passwordEncoder: Adiciona segurança nas senhas, agora só aceita senhas criptografadas com esse formato BCrypt;

        auth.userDetailsService(authService)
            .passwordEncoder(new BCryptPasswordEncoder());
    }

    @Override //Configurações de Autorização
    protected void configure(HttpSecurity http) throws Exception {

        /* authorizeRequest: Método para configuração de autorizações de requisições.
         * antMatchers: Método de mapeamento de autorizações personalizadas.
         *      ps.:    - Aceita o Méthod em questão como primeiro argumento;
         *              - Segundo argumento é o mapeamento que quer ajustar a permissão;
         *      ps2.:   - Caso na url da requisição contenha uma pathVariable se faz necessário colocar um '*'
         * anyRequest().autenticated(): Pra qualquer requisição que nao foi configurada, se faz necessário tá autenticado.
         *      ps.: Requer ter configurado as configs de autenticações.
         *
         * and: Adicionar Mais comandos.
         *
         * formLogin: Gerar automaticamente um Form de autenticação, juntamente com um Controller
         *            que servirá para as requisições desse formulário. (Isso tudo fica por debaixo dos panos)
         */

        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers(HttpMethod.POST, "/user").permitAll()
                .antMatchers(HttpMethod.GET, "/user/*").permitAll()
                .anyRequest().authenticated()

                .and()
                .formLogin();
    }

    @Override //Configurações de Recursos estáticos (js, css, imagens, etc.)
    public void configure(WebSecurity web) throws Exception {

    }

    // Gerar uma senha encriptada de forma prática para testes.
    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder().encode("123"));
    }

}
