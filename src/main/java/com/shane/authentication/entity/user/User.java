package com.shane.authentication.entity.user;

import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;

@Data
@Entity
@Table(name = "user")
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "password", nullable = true)
    private String password;

    @Column(name = "email", nullable = false)
    private String email;

    @ManyToOne
    @JoinColumn(name="auth_type", nullable = false)
    private AuthType authType;

}
