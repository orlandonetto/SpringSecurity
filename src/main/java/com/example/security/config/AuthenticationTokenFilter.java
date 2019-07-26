package com.example.security.config;

import com.example.security.models.User;
import com.example.security.services.UserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Scanner;

// Esse filtro será executado no inicio das requisições.
public class AuthenticationTokenFilter extends OncePerRequestFilter {

    private TokenService tokenService;

    private UserService userService;

    public AuthenticationTokenFilter(TokenService tokenService, UserService userService) {
        this.tokenService = tokenService;
        this.userService = userService;
    }

    /* OncePerRequestFilter
     *  -> Filtro do Spring que é executado uma única vez a cada requisição


     * TokenService: Não é possivel Injetar com o @Autowired nos tipos Filter. Com isso, se faz necessário passar pelo
     *      construtor.
     *


     * doFilterInternal(request, response, filterChain)
     *  -> É necessário o filterChain.doFilter(request, response) no final do método, pra dizer ao Spring que ja realizou
     *     o que tinha que fazer no filtro, e com isso a API seguir o fluxo;
     *
     *  -> No nosso caso, a lógica desse filtro, será pegar o token no header do request e verificar se é valido.
     *  -> A autenticação pelo filtro será feita a cada requisição, já que a API seguirá os principios do Rest, e ser Stateless;
     *

     * checkToken()
     *  -> Verifica e retorna o token informado no Header
     *  -> O token, por padrão tem as seguintes caracteristicas:
     *      - Header Key: 'Authorization'
     *      - Header Value: 'Bearer <token>'
     *
     * AuthenticateUser:
     *      1. Precisamos saber quem é o Usuário, com isso vamos até o tokenService, e pegamos o Id que tá dento do JWT;
     *      2. Vamos até o banco de dados e pegamos o usuário com o id que foi retornado anteriormente;
     *      3. Precisamos atribuir o usuário, a senha e o perfil de usuário para o UsernamePasswordAuthenticationToken.
     *              obs: A senha está passando como Null, pq anteriormente já foi validada pelo método isValid();
     *      4. Forçamos a adição do usuário com a classe do Spring security (SecurityContextHolder) pois só possuimos o IdUser;
     *              obs: A classe AuthenticationManager deve ser utilizada apenas na lógica de autenticação
     *                   via username/password, para a geração do token.
     *
     *   OBS: O processo sempre se repeta a cada requisição, já que a API está no modo STATELESS;
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        //printRequest(request);

        // Pegar o token (JWT) através do Header da requisição (Request)
        String token = checkToken(request);

        //System.out.println(token);

        // Verificar se o Token informado é realmente válido.
        boolean valid = tokenService.isValid(token);

        // Autenticar Usuário
        if (valid)
            authenticateUser(token);


        filterChain.doFilter(request, response);
    }

    private void authenticateUser(String token) {
        Integer idUser = tokenService.getIdUser(token);

        User user = userService.getUser(idUser);

        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private String checkToken(HttpServletRequest request) {
        String token = request.getHeader("Authorization");

        //System.out.println(token);

        if (token == null || token.isEmpty() || !token.startsWith("Bearer "))
            return null;

        return token.substring(7);
    }


    // Mostrar todos os dados da requisição que foi recebida.
    private void printRequest(HttpServletRequest request) throws IOException {

        // HEADERS
        System.out.println("\n\nHEADERS");
        Enumeration headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = (String) headerNames.nextElement();
            System.out.println(headerName + " = " + request.getHeader(headerName));
        }

        // PARAMETERS
        System.out.println("\n\nPARAMETERS");
        Enumeration params = request.getParameterNames();
        while (params.hasMoreElements()) {
            String paramName = (String) params.nextElement();
            System.out.println(paramName + " = " + request.getParameter(paramName));
        }

        // BODY
        System.out.println("\n\nBODY");
        Scanner scanner = new Scanner(request.getInputStream(), "UTF-8").useDelimiter("\\A");
        System.out.println(scanner.hasNext() ? scanner.next() : "");
    }

}
