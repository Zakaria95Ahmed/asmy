package com.bdt.asmy.Model.Mappers;

import com.bdt.asmy.Model.DTOS.UserDTO;
import com.bdt.asmy.Model.UsersAccount;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserMapper {

    public UserDTO toUserDTO(UsersAccount user) {
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(user, userDTO);
        return userDTO;
    }

    public UsersAccount toUser(UserDTO userDTO) {
        UsersAccount user = new UsersAccount();
        BeanUtils.copyProperties(userDTO, user);
        return user;
    }


    public List<UserDTO> mapToUserDTOList(List<UsersAccount> Users) {
        return Users.stream()
                .map(this::toUserDTO)
                .collect(Collectors.toList());
    }

}
