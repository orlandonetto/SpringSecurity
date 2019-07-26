package com.example.security.config;

import com.example.security.models.User;
import com.example.security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationService implements UserDetailsService {

    // Classe Service que contem a lógica de Autenticação do User

    @Autowired
    UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        /*  Método que é executado, exatamente no momento que o usuário tenta se autenticar no form de login
         *  gerado pelo Spring Security, isso se dá pelo fato da classe herdar de UserDetailService.
         *
         *  String username: Parâmetro recebe o valor que foi digitado no campo username na tela de Login.
         *
         *  OBS.: Só é passado o username por parâmetro, mas o spring também faz uma verificação pela senha
         *        automaticamente em memória, no final das contas ele verifica o username de forma manual pelo
         *        repository, e enquanto verifica por lá, ele tb compara com a senha informada no form, por debaixo
         *        dos panos.
         *
         *  Optional<User>: Classe do Java.util que serve para nao estourar erro caso nao encontre o usuário.
         *                  Diante disso, fazemos a verificação se o user.isPresente() ou seja, se encontrou o usuário
         *                  informado, caso tenha encontrado retorne o usuário (return user.get()) caso contrário
         *                  lance uma exception com uma mensagem de erro.
         */

        Optional<User> user = repository.findByUsername(username);

        if(user.isPresent())
            return user.get();

        throw new UsernameNotFoundException("Dados Inválidos!");
    }
}
