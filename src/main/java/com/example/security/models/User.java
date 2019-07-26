package com.example.security.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String name;

    private String username;

    private String password;

    /*  A classe precisa implementar o UserDetails, pra mostrar ao Spring Security onde
     *  está representado os detalhes(Details) para autenticações de usuários.
     *
     *  Métodos de controle de usuário (Details)
     *  isEnabled: Se o usuário está ativo;
     *  isCredentialsNonExpired: Se as credenciais do usuário nao está expirada;
     *  isAccountNonExpired: Se a conta não está expirada
     *  isNonLocked: Se o usuário não está bloqueado;
     *      ps.: Caso o usuário esteja tudo certo, e tudo ok, todos esses métodos acima devem receber {true};
     *
     *  getAuthorities: O Spring Security solicita saber a qual perfil/grupo do usuário, pois
     *                  os perfis estão relacionados com as permissões de acesso do usuário.
     *      ps.: Se faz necessário criar uma Collection com todos os perfis dos usuários e colocar no retorno
     *           método.
     *  List<Perfil>: Lista com todos os perfis de permissões dos usuários, é necessário ser uma entity, para que
     *                seja salvo no banco de dados, e deve possuir os seguintes atributos:
     *                  Id e nome;
     *      ps.: A classe Perfil é necessário implementar a interfaec GrantedAuthority, pra mostrar ao Spring
     *           Security, qual é a clase que representa o perfil de acesso. Em consequencia disso, se faz
     *           necessário sobrescrever o método getAuthority, onde deverá ser retornado o nome do perfil.
     *
     *  Perfil: A classe Perfil precisa ser uma Entity, com isso se faz necessário que possua uma cardinalidade,
     *          seguindo a seguinte lógica: UM Usuário pode ter MUITOS perfis, e UM perfil pode ter MUITOS usuários,
     *          resutando em uma cardinalidade do tipo N:N (ManyToMany)
     *      ps.: No mapeamento ManyToMany, quando for realizado uma solicitação o usuário pelo banco de dados,
     *           é interessante mostrar toda a lista com os perfis do usuário solicitado, com isso foi adicionado
     *           dentro da anotação o (fetch = FetchType.EAGER)
     */

    @ManyToMany(fetch = FetchType.EAGER)
    private List<Perfil> perfis = new ArrayList<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.perfis;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
