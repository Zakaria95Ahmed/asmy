package com.bdt.asmy.Controller;

import com.bdt.asmy.Exception.*;
import com.bdt.asmy.Model.HTTPResponse;
import com.bdt.asmy.Model.UserData;
import com.bdt.asmy.Model.UsersAccount;
import com.bdt.asmy.Service.UserService;
import com.bdt.asmy.Utility.JWTProvider;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping(path = {"/", "/user"})
@RequiredArgsConstructor
public class UserController extends ExceptionProcessing {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JWTProvider jWTProvider;
//    private final UsersAccountRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String DisplayUserOnly() {
        return "First Spring boot Controller display in Website";
    }

    @PostMapping("/login")
    public ResponseEntity<UsersAccount> login(@RequestBody UsersAccount user) {
        asmyAuthenticaton(user.getUsername(), user.getPassword());
        UsersAccount login = userService.findByUsername(user.getUsername());
        UserData userData = new UserData(login);
        HttpHeaders jwtHeader = getasmyJwtHeader(userData);
        return new ResponseEntity<>(login, jwtHeader, OK);
    }


    @PostMapping("/register")
    public ResponseEntity<UsersAccount> register(@Valid @RequestBody UsersAccount userData) throws UsernameNotExist, UsernameExist, EmailExist, PasswordValidException, MessagingException {
        userService.register(userData.getFirstName(), userData.getLastName(), userData.getUsername(), userData.getEmail(), userData.getPassword());
        return new ResponseEntity<>(userData, HttpStatus.OK);
    }

    @PostMapping("/add")
    public ResponseEntity<UsersAccount> addNewUser(@RequestParam("firstName") String firstName,
                                                   @RequestParam("lastName") String lastName,
                                                   @RequestParam("username") String username,
                                                   @RequestParam("email") String email,
                                                   @RequestParam("role") String role,
                                                   @RequestParam("isActive") String isActive,
                                                   @RequestParam("isNonLocked") String isNonLocked)

            throws UsernameNotExist, UsernameExist, EmailExist, IOException {
        UsersAccount newUser = userService.addNewUser(firstName, lastName, username, email, role, Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive));
        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/update")
    public ResponseEntity<UsersAccount> update(@RequestParam("currentUsername") String currentUsername,
                                               @RequestParam("firstName") String firstName,
                                               @RequestParam("lastName") String lastName,
                                               @RequestParam("username") String username,
                                               @RequestParam("email") String email,
                                               @RequestParam("role") String role,
                                               @RequestParam("isActive") String isActive,
                                               @RequestParam("isNonLocked") String isNonLocked)

            throws UsernameNotExist, UsernameExist, EmailExist, IOException {
        UsersAccount updatedUser = userService.updateUser(currentUsername, firstName, lastName, username, email, role, Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive));
        return new ResponseEntity<>(updatedUser, OK);
    }

    //assad
    @PostMapping("/changePassword")
    public ResponseEntity<String> changePassword(@RequestBody HashMap<String, String> request) {
        String username = request.get("username");
        UsersAccount user = userService.findByUsername(username);
        if (user == null) {
            return new ResponseEntity<>("User not found!", HttpStatus.BAD_REQUEST);
        }
        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");
        String confirmPassword = request.get("confirmPassword");
        if (!newPassword.equals(confirmPassword)) {
            return new ResponseEntity<>("PasswordNotMatched", HttpStatus.BAD_REQUEST);
        }
        String userPassword = user.getPassword();
        try {
            if (!newPassword.isEmpty() && !StringUtils.isEmpty(newPassword)) {
                if (bCryptPasswordEncoder.matches(currentPassword, userPassword)) {
                    userService.changePassword(user, newPassword);
                }
            } else {
                return new ResponseEntity<>("IncorrectCurrentPassword", HttpStatus.BAD_REQUEST);
            }
            return new ResponseEntity<>("Password Changed Successfully!", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error Occurred: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }


    @DeleteMapping("/delete/{username}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<HTTPResponse> deleteUser(@PathVariable("username") String username) throws IOException {
        userService.deleteUser(username);
        return response(OK, "User delete successfully");
    }

    @GetMapping("/find/{username}")
    public ResponseEntity<UsersAccount> getUser(@PathVariable("username") String username) {
        UsersAccount user = userService.findByUsername(username);
        return new ResponseEntity<>(user, OK);
    }


    @GetMapping("/list")
    public ResponseEntity<List<UsersAccount>> getAllUsers() {
        List<UsersAccount> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    private ResponseEntity<HTTPResponse> response(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(new HTTPResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(),
                message), httpStatus);
    }

    private HttpHeaders getasmyJwtHeader(UserData user) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Jwt-Token", jWTProvider.generateJwtToken(user));
        return headers;
    }

    private void asmyAuthenticaton(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }


    @GetMapping("/resetPassword/{email}")
    public ResponseEntity<HTTPResponse> resetPassword(@PathVariable("email") String email) throws MessagingException, EmailNotExist {
        userService.resetPassword(email);
        return response(OK, "An email with a new password was sent to: " + email);
    }

}
