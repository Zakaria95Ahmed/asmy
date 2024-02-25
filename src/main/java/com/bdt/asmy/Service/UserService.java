package com.bdt.asmy.Service;

import com.bdt.asmy.Exception.*;
import com.bdt.asmy.Model.UsersAccount;

import jakarta.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    void register(String firstName, String lastName, String username, String email, String password) throws UsernameNotExist, UsernameExist, EmailExist, MessagingException, PasswordValidException;

    List<UsersAccount> getUsers();

    UsersAccount findByUsername(String username);

    UsersAccount findByEmail(String email);

    UsersAccount addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive) throws UsernameNotExist, UsernameExist, EmailExist, IOException;

    UsersAccount updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive) throws UsernameNotExist, UsernameExist, EmailExist, IOException;
    void deleteUser(String username) throws IOException;
    void changePassword(UsersAccount user, String newPassword) throws MessagingException, PasswordValidException;

    void resetPassword(String email) throws MessagingException, EmailNotExist;

}
