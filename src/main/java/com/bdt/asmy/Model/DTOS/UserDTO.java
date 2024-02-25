package com.bdt.asmy.Model.DTOS;

import com.bdt.asmy.Model.StringArrayConverter;
import jakarta.persistence.Convert;
import jakarta.persistence.Lob;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
public class UserDTO {

    private Long id;

    @NotNull(message = "firstName is required")
    @Size(min = 4, max = 20, message = "firstName must be between 4 and 20 characters")
    private String firstName;

    @NotNull(message = "lastName is required")
    @Size(min = 4, max = 20, message = "lastName must be between 4 and 20 characters")
    private String lastName;

    @NotNull(message = "Username is required")
    @Size(min = 4, max = 20, message = "Username must be between 4 and 20 characters")
    private String username;

    @NotNull(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;
    private String password;
    private String role;
    @Lob
    @Convert(converter = StringArrayConverter.class)
    private String[] authorities;

    // Omit password for security reasons, or use carefully for account creation/updating

    // Don't include password in DTO for security reasons


}
