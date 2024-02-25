package com.bdt.asmy.Implementation;

import com.bdt.asmy.Exception.*;
import com.bdt.asmy.Model.UserData;
import com.bdt.asmy.Model.UsersAccount;
import com.bdt.asmy.Permission.UserRolesAuthentications;
import com.bdt.asmy.Repository.UsersAccountRepository;
import com.bdt.asmy.Service.LoginAttempts;
import com.bdt.asmy.Service.ServiceAllEmail;
import com.bdt.asmy.Service.UserService;
import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.cryptacular.bean.EncodingHashBean;
import org.cryptacular.spec.CodecSpec;
import org.cryptacular.spec.DigestSpec;
import org.passay.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static com.bdt.asmy.Permission.UserRolesAuthentications.ROLE_SUPER_ADMIN;
import static org.apache.commons.lang3.StringUtils.EMPTY;

@Service
@Transactional
@Qualifier("bdtasmyuserDetailsService")
@Slf4j
@RequiredArgsConstructor
public class UserServiceImplementation implements UserService, UserDetailsService {


    private final UsersAccountRepository userRepo;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final LoginAttempts loginAttemptService;
    private final ServiceAllEmail emailService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UsersAccount user = userRepo.findByUsername(username);
        if (user == null) {
            log.error("No user found by username: " + username);
            throw new UsernameNotFoundException("No user found by username:" + username);
        } else {
            UserLoginAttemptValidation(user);

            userRepo.save(user);
            UserData userData = new UserData(user);
            log.info("The user ( " + username + " ) found ");
            return userData;
        }
    }

    private void UserLoginAttemptValidation(UsersAccount user) {
        if (user.isNotLocked()) {
            if (loginAttemptService.userOverpassMaxAttempts(user.getUsername())) {
                user.setNotLocked(false);
            } else {
                user.setNotLocked(true);
            }
        } else {
            loginAttemptService.RemoveUserAttemptFromCache(user.getUsername());
        }
    }

    @Override
    public void register(String firstName, String lastName, String username, String email, String password)
            throws UsernameNotExist, UsernameExist, EmailExist, PasswordValidException, MessagingException {


        isvalidUsernameAndEmail(EMPTY, username, email);
        //ConstraintValidatorContext context = null;
        isValid(password);
        //matches(  password,  confirmPassword);
        UsersAccount user = new UsersAccount();
        // new ApiResponse(user, "success");

        user.setUserId(generateUserId());
        // assad String password = generatePassword();
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);


        user.setPassword(encodePassword(password));

        user.setActive(true);
        user.setNotLocked(true);
        user.setRole(ROLE_SUPER_ADMIN.name());//USER_PERMISSIONS
        user.setAuthorities(ROLE_SUPER_ADMIN.getAuthorities());


        userRepo.save(user);
        log.info("New user password: " + password);
        emailService.sendNewPasswordEmail(firstName, password, email);


    }

    private UsersAccount isvalidUsernameAndEmail(String currentUsername, String newUsername, String newEmail) throws UsernameNotExist, UsernameExist, EmailExist {
        UsersAccount userByNewUsername = findByUsername(newUsername);
        UsersAccount userByNewEmail = findByEmail(newEmail);
        if (StringUtils.isNotBlank(currentUsername)) {
            UsersAccount currentUser = findByUsername(currentUsername);
            if (currentUser == null) {
                throw new UsernameNotExist("No user found by username: " + currentUsername);
            }
            if (userByNewUsername != null && !currentUser.getId().equals(userByNewUsername.getId())) {
                throw new UsernameExist("Username already exists");
            }
            if (userByNewEmail != null && !currentUser.getId().equals(userByNewEmail.getId())) {
                throw new EmailExist("Email are already exists");
            }
            return currentUser;
        } else {
            if (userByNewUsername != null) {
                throw new UsernameExist("Username already exists");
            }
            if (userByNewEmail != null) {
                throw new EmailExist("Email are already exists");
            }
            return null;
        }
    }


    @SneakyThrows
    public boolean isValid(String password) {
        String messageTemplate = null;
        Properties props = new Properties();
        InputStream inputStream = getClass()
                .getClassLoader().getResourceAsStream("passay.properties");
        try {
            props.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        MessageResolver resolver = new PropertiesMessageResolver(props);

        //assad
        List<PasswordData.Reference> history = Arrays.asList(
                // Password=P@ssword1
                new PasswordData.HistoricalReference(
                        "SHA256",
                        "j93vuQDT5ZpZ5L9FxSfeh87zznS3CM8govlLNHU8GRWG/9LjUhtbFp7Jp1Z4yS7t"),

                // Password=P@ssword2
                new PasswordData.HistoricalReference(
                        "SHA256",
                        "mhR+BHzcQXt2fOUWCy4f903AHA6LzNYKlSOQ7r9np02G/9LjUhtbFp7Jp1Z4yS7t"),

                // Password=P@ssword3
                new PasswordData.HistoricalReference(
                        "SHA256",
                        "BDr/pEo1eMmJoeP6gRKh6QMmiGAyGcddvfAHH+VJ05iG/9LjUhtbFp7Jp1Z4yS7t")
        );
        EncodingHashBean hasher = new EncodingHashBean(
                new CodecSpec("Base64"), // Handles base64 encoding
                new DigestSpec("SHA256"), // Digest algorithm
                1, // Number of hash rounds
                false); // Salted hash == false
        //assad
        PasswordValidator validator = new PasswordValidator(resolver, Arrays.asList(

                // length between 8 and 16 characters
                new LengthRule(8, 16),

                // at least one upper-case character
                new CharacterRule(EnglishCharacterData.UpperCase, 1),

                // at least one lower-case character
                new CharacterRule(EnglishCharacterData.LowerCase, 1),

                // at least one digit character
                new CharacterRule(EnglishCharacterData.Digit, 1),

                // at least one symbol (special character)
                new CharacterRule(EnglishCharacterData.Special, 1),


                // no whitespace
                new WhitespaceRule(),

                // rejects passwords that contain a sequence of >= 3 characters alphabetical  (e.g. abc, ABC )
                new IllegalSequenceRule(EnglishSequenceData.Alphabetical, 3, false),
                // rejects passwords that contain a sequence of >= 3 characters numerical   (e.g. 123)
                new IllegalSequenceRule(EnglishSequenceData.Numerical, 3, false)
                //assad
                , new DigestHistoryRule(hasher)
                //assad
        ));

        RuleResult result = validator.validate(new PasswordData(password));


        PasswordData data = new PasswordData("P@ssword1", password);//"P@ssword1");
        data.setPasswordReferences(history);
        RuleResult result2 = validator.validate(data);


        if (result.isValid()) {
            return true;
        }
        try {
            if (result.isValid() == false) {
                List<String> messages = validator.getMessages(result);

                messageTemplate = String.join(",", messages);

                System.out.println("Invalid Password: " + validator.getMessages(result));
            }
        } finally {
            throw new PasswordValidException(messageTemplate);

        }

    }


    @Override
    public UsersAccount addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive) throws UsernameNotExist, UsernameExist, EmailExist, IOException {
        isvalidUsernameAndEmail(EMPTY, username, email);
        UsersAccount user = new UsersAccount();
        String password = generatePassword();
        user.setUserId(generateUserId());
        user.setFirstName(firstName);
        user.setLastName(lastName);

        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(encodePassword(password));
        user.setActive(isActive);
        user.setNotLocked(isNonLocked);
        user.setRole(getRoleEnumName(role).name());
        user.setAuthorities(getRoleEnumName(role).getAuthorities());

        userRepo.save(user);

        log.info("New user password: " + password);
        return user;
    }


    @Override
    public void changePassword(UsersAccount user, String newpassword) throws MessagingException, PasswordValidException {
        isValid(newpassword);
        String encryptedPassword = bCryptPasswordEncoder.encode(newpassword);
        user.setPassword(encryptedPassword);
        userRepo.save(user);
        emailService.sendNewPasswordEmail(user.getFirstName(), newpassword, user.getEmail());


    }

    @Override
    public UsersAccount updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive) throws UsernameNotExist, UsernameExist, EmailExist, IOException {
        UsersAccount currentUser = isvalidUsernameAndEmail(currentUsername, newUsername, newEmail);
        currentUser.setFirstName(newFirstName);
        currentUser.setLastName(newLastName);
        currentUser.setUsername(newUsername);
        currentUser.setEmail(newEmail);
        currentUser.setActive(isActive);
        currentUser.setNotLocked(isNonLocked);
        currentUser.setRole(getRoleEnumName(role).name());
        currentUser.setAuthorities(getRoleEnumName(role).getAuthorities());
        userRepo.save(currentUser);

        return currentUser;
    }

    @Override
    public void deleteUser(String username) throws IOException {
        UsersAccount user = userRepo.findByUsername(username);
        userRepo.deleteById(user.getId());
    }


    @Override
    public List<UsersAccount> getUsers() {
        return userRepo.findAll();
    }

    @Override
    public UsersAccount findByUsername(String username) {
        return userRepo.findByUsername(username);
    }

    @Override
    public UsersAccount findByEmail(String email) {
        return userRepo.findByEmail(email);
    }

    private UserRolesAuthentications getRoleEnumName(String role) {
        return UserRolesAuthentications.valueOf(role.toUpperCase());
    }

    private String encodePassword(String password) {
        return bCryptPasswordEncoder.encode(password);
    }

    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    private String generateUserId() {
        return RandomStringUtils.randomNumeric(10);
    }


    @Override
    public void resetPassword(String email) throws MessagingException, EmailNotExist {
        UsersAccount user = userRepo.findByEmail(email);
        if (user == null) {
            throw new EmailNotExist("No user found for email: " + email);
        }
        String password = generatePassword();
        String encryptedPassword = bCryptPasswordEncoder.encode(password);
        user.setPassword(encryptedPassword);
        userRepo.save(user);
        log.info("New user password: " + password);
        emailService.sendNewPasswordEmail(user.getFirstName(), password, user.getEmail());
    }


}
