package com.programmers.devcourse.application.user.service;

import com.programmers.devcourse.application.group.model.Group;
import com.programmers.devcourse.application.group.repository.GroupRepository;
import com.programmers.devcourse.application.user.model.User;
import com.programmers.devcourse.application.user.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static org.apache.logging.log4j.util.Strings.isNotEmpty;

@Service
public class UserService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final UserRepository userRepository;

    private final GroupRepository groupRepository;

    public UserService(UserRepository userRepository, GroupRepository groupRepository) {
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
    }

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        checkArgument(isNotEmpty(username), "username must me provided");
        return userRepository.findByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
        checkArgument(isNotEmpty(provider), "provider must me provided");
        checkArgument(isNotEmpty(providerId), "providerId must me provided");

        return userRepository.findByProviderAndProviderId(provider, providerId);
    }

    @Transactional
    public User join(OAuth2User oAuth2User, String provider) {
        checkArgument(oAuth2User != null, "oAuth2User must me provided");
        checkArgument(isNotEmpty(provider), "provider must me provided");

        String providerId = oAuth2User.getName();
        return findByProviderAndProviderId(provider, providerId)
                .map(user -> {
                    log.warn("Already exists : {} for provider : {} providerId : {}", user, provider, providerId);
                    return user;
                })
                .orElseGet(() -> {
                    Map<String, Object> attributes = oAuth2User.getAttributes();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");

                    checkArgument(properties != null, "OAuth2User properties is empty");

                    String nickname = (String) properties.get("nickname");
                    String profileImage = (String) properties.get("profile_image");
                    Group group = groupRepository.findByName("USER_GROUP")
                            .orElseThrow(() -> new IllegalArgumentException("Could not found group for USER_GROUP"));
                    return userRepository.save(
                            new User(
                                    nickname,
                                    provider,
                                    providerId,
                                    profileImage,
                                    group
                            )
                    );
                });

        /**
         * username - 카카오 닉네임
         * provider - provider 파라미터
         * providerId - oAuth2User.getName();
         * profileImage - 카카오 인증된 사용자의 프로필 이미지를 사용
         * group - USER_GROUP Group
         */
    }
}
