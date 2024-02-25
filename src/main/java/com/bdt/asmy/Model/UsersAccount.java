package com.bdt.asmy.Model;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.lang.NonNull;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;

@Data // @Data From import lombok.Data will create all Setter and Getter
@Entity
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
public class UsersAccount implements Serializable { //VIP @Data From import lombok.Data will create all Setter and Getter

    @Serial
    private static final long serialVersionUID = 8709776255922620598L;

    // Auto Generated Values. The value can be AUTO, TABLE, SEQUENCE, or IDENTITY.
    //	Marking a field with the @GeneratedValue annotation specifies that a value will be automatically generated for that field.
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String userId;

    @NonNull
    private String firstName;
    @NonNull
    private String lastName;
    @NonNull
    private String username;

    @Email
    @NonNull
    private String email;
    @NonNull
    private String password;

    // @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String role;

    @Lob
    @Convert(converter = StringArrayConverter.class)
    private String[] authorities;

    private boolean isActive;// Enable/Disable
    private boolean isNotLocked;//Locked/UnLocked

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "last_updated")
    private LocalDateTime lastUpdated;

}
