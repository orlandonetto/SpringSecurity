package com.example.security.config;

import com.example.security.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity //Habilita o módulo de segurança na aplicação
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired // classe service que tem a lógica de autenticação.
    private AuthenticationService authService;

    /* Necessita ser injetado nessa classe, para passar como parâmetro no Filter, ja que o filterToken foi
       instanciado manualmente por nós. */
    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserService userService;

    @Override
    @Bean // É preciso transformar em @Bean para que seja possivel usar o @Autowired no AuthenticationController;
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override //Configurações de autenticação
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // passwordEncoder: Adiciona segurança nas senhas, agora só aceita senhas criptografadas com esse formato BCrypt;

        auth.userDetailsService(authService)
                .passwordEncoder(new BCryptPasswordEncoder());
    }

    @Override //Configurações de Autorização
    protected void configure(HttpSecurity http) throws Exception {

        //(Autenticação Tradicional, User + Pass, Session)
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

        //(JWT, STATELESS)
        /* No modelo de sessão, o servidor guarda um JSessionID para cada usuário logado e contém em memória
         * Dados do cliente, já o cliente recebe o id da seesao dele como um Cookie. Esse modelo em APIs Rest não
         * é uma boa prática, pois o sistema deixa de ter escalabilidade com isso seria adequado trabalhar com Tokens,
         * para que assim, a conexão se torne Stateless.
         *      ps.: Stateless é um protocolo que considera cada requisição como independente, ou seja não mantem
         *           a conexão com o servidor. Em outras palavras, o cliente faz a requisição, o servidor processa e
         *           envia a resposta, e a conexão é encerrada.
         * JWT -> Para se trabalhar com tokens, uma boa opção é o JSON Web Token, que é um token codificado que é gerado
         *        pra o cliente. O JWT serve como autenticador via token, onde na primeira requisição do cliente, o servidor
         *        envia um JWT pra o cliente, com isso o cliente fica responsável por guardar esse token, e quando fizer
         *        novas requisições para o servidor, deve ser enviado o JWT, o servidor por sua vez verifica o JWT enviado,
         *        e com ele é possivel verificar se o usuário está autenticado ou não.
         *
         * - Stateless -
         * Remoção do .formLogin: Se faz necessário remover esse método pois o login gerenciado pelo spring security, por
         *      padrão cria a sessão do cliente, e nesse caso, queremos deixar Stateless.
         * .csrf: Cross-Site Request Forgery (em português falsificação de solicitação entre sites) é um tipo de ataque
         *        hacker que quando a aplicação é stateless e usa JWT, nao se faz necessário deixar habilitado. Inclusive
         *        é necessário desabilitar para que o JWT funcione corretamente.
         * .sessionManagement: Gerenciador de Sessão;
         * .sessionCreationPolicy: Política de criação de sessão;
         * .SessionCreationPolicy.STATELESS: Transforma o servidor em STATELESS
         *      resumindo: Informou ao Spring Security, que quando fizer uma autenticação, não é pra gerar uma sessão pra
         *                 o cliente.
         *      OBS: Como foi removido a session, e adicionado o modo Stateless, teve que ser removido o login gerenciado
         *           pelo spring, em consequencia disso, o controllerLogin que era gerado por debaixo dos panos, tb foi
         *           removido automaticamente, com isso, há a necessidade de criar o AuthenticationController.
         *
         * .addFilterBefore(YourFilter, filter): Tem como função, fazer com que a API execute um filtro antes de excutar
         *                                       o fluxo normal;
         *      ps.: Os parametros são o Filtro que quer adicionar, e o filtro no qual ele será executado antes.
         *
         * AuthenticationTokenFilter: Classe que gerencia o filtro de Tokens.
         *
         */

        http.authorizeRequests()
                .antMatchers("/test").permitAll()
                .antMatchers(HttpMethod.POST, "/user").permitAll()
                .antMatchers(HttpMethod.GET, "/user/*").permitAll()
                .antMatchers(HttpMethod.POST, "/auth").permitAll()
                .anyRequest().authenticated()

                /*
                .and()
                .formLogin();
                 */

                .and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .addFilterBefore(new AuthenticationTokenFilter(tokenService, userService), UsernamePasswordAuthenticationFilter.class);
    }

    @Override //Configurações de Recursos estáticos (js, css, imagens, etc.)
    public void configure(WebSecurity web) throws Exception {

    }

    // Gerar uma senha encriptada de forma prática para testes.
    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder().encode("123"));
    }

}
