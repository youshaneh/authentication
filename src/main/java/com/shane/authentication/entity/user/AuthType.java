package com.shane.authentication.entity.user;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "auth_type")
public class AuthType implements Serializable {
    public static AuthType SITE = new AuthType(1, "site");
    public static AuthType GOOGLE = new AuthType(2, "google");

    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "platform", nullable = false)
    private String platform;

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof AuthType)) return false;
        AuthType authType = (AuthType) o;
        return id.equals(authType.id) && platform.equals(authType.platform);
    }

    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + id.hashCode();
        result = 31 * result + platform.hashCode();
        return result;
    }
}
