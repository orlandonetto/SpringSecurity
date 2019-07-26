package com.example.security.config;

import com.example.security.dtos.LoginForm;
import com.example.security.dtos.TokenDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    /* @RequestBody: Obriga que quem fazer a requisção ao endpoint, envie um Objeto (Body);
     * @Valid: Faz a validação para verificar se o objeto que foi passado está válido, ou seja, se os dados estão diferente
     *         de null, e se corresponde aos tipos informados;
     * LoginForm: DTO somente com os dados necessários para realizar a autenticação;
     *
     */

    /* AuthenticationManager
     *      -> Pra realizar a autenticação precisamos da classe AuthenticationManager, pois retiramos o Controller automático
     *         do Spring Security
     *      -> OBS: O Spring nao consegue fazer o @Autowired automaticamente nessa classe, com isso, é preciso configurar
     *              no service
     */

    /* auth()
     * AuthenticationManager: Pra realizar a autenticação precisamos da classe AuthenticationManager, pois retiramos o
     *          controller automático do Spring Security
     *      ps: O Spring nao consegue fazer o @Autowired automaticamente nessa classe, com isso, é preciso
     *          configurar no WebSecurityConfig, pois é la onde herda da classe WebSecurityConfigurerAdapter.
     *
     * authenticate(): Método que vai realizar a autenticação, recebendo um objeto do tipo UsernamePasswordAuthenticationToken;
     *             ps: Ao executar o  authManager.authenticate(), o spring passa a executar o AuthenticateService, para realizar
     *                 a autenticação.
     * Authentication: Interface de autenticação.
     *
     */

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired  // Classe responsável por gerar e validar os tokens.
    private TokenService tokenService;

    @PostMapping()
    public ResponseEntity<?> auth(@RequestBody @Valid LoginForm loginForm) {

        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginForm.getUsername(), loginForm.getPassword()));

            // Gerar Token
            String token = tokenService.generateToken(authentication);

            // Criar TokenDto, passando o JWT e o Header de autenticação que deverá utilizar.
            TokenDto tokenDto = new TokenDto(token, "Bearer");

            return ResponseEntity.ok(token);
        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest().build();
        }

    }

}
