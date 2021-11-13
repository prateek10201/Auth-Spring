package com.sfuit.Auth.repository;

import com.sfuit.Auth.entity.Token;
import com.sfuit.Auth.entity.User;
import com.sfuit.Auth.exceptions.EtAuthException;

public interface UserRepository {

    Integer create(String name, String email, String dob, String phone, String password, String otp, String token, String is_verified, String device_id, String device_token) throws EtAuthException;

    User findByEmailandPassword(String email, String password) throws EtAuthException;

    Integer getCountByEmail(String email);
    Integer getCountByPhone(String phone);
    User findById(Integer userId);

    User findByEmailandOTP(String email, String otp) throws EtAuthException;

    Integer addUpdatedToken(String email, String token, String device_id);

    Token findByEmail(String email);

    User findByEmailandUpdateDeviceToken(String email, String device_token);
}
