package com.programmers.devcourse.application.group.repository;

import com.programmers.devcourse.application.group.model.Group;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GroupRepository extends JpaRepository<Group, Long> {

    Optional<Group> findByName(String name);
}
