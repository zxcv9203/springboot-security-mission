package com.programmers.devcourse.application.group_permission.model;

import com.programmers.devcourse.application.group.model.Group;
import com.programmers.devcourse.application.permission.model.Permission;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import javax.persistence.*;

@Entity
@Table(name = "group_permission")
public class GroupPermission {

    @Id
    @Column(name = "id")
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "group_id")
    private Group group;

    @ManyToOne(optional = false)
    @JoinColumn(name = "permission_id")
    private Permission permission;

    public Long getId() {
        return id;
    }

    public Group getGroup() {
        return group;
    }

    public Permission getPermission() {
        return permission;
    }
}
