package com.bdt.asmy.Permission;

import com.bdt.asmy.Model.UserData;
import com.bdt.asmy.Service.LoginAttempts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class LoginAttemptsSuccess {
    private final LoginAttempts loginAttemptService;

    @Autowired
    public LoginAttemptsSuccess(LoginAttempts loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        if(principal instanceof UserData) {
            UserData user = (UserData) event.getAuthentication().getPrincipal();
            loginAttemptService.RemoveUserAttemptFromCache(user.getUsername());
        }
    }
}
