package com.programmers.devcourse.application.user.repository;

import com.programmers.devcourse.application.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    @Query("select u from User u join fetch u.group g left join fetch g.permissions gp join fetch gp.permission where u.loginId = :loginId")
    Optional<User> findByLoginId(String loginId);

}
