package com.bdt.asmy.Repository;

import com.bdt.asmy.Model.UsersAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UsersAccountRepository extends JpaRepository<UsersAccount, Long> {

    UsersAccount findByUsername(String username);
    UsersAccount findByEmail(String email);




}
