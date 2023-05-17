package com.meta.StudyJwt.config.auth;

import com.meta.StudyJwt.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    public User getUser() {
        return user;
    }

    // 계정의 권한을 return
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(r -> {
            authorities.add(() -> r);
        });
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정이 만료? (true: 만료안됨)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠겨있는지? (true:unlock)
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 비밀번호 만료? (true:NonExpired)
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 활성화? (true:활성화)
    @Override
    public boolean isEnabled() {
        return true;
    }
}
