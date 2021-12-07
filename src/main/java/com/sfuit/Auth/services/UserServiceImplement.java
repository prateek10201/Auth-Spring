package com.sfuit.Auth.services;

import com.sfuit.Auth.entity.Token;
import com.sfuit.Auth.entity.User;
import com.sfuit.Auth.exceptions.EtAuthException;
import com.sfuit.Auth.exceptions.EtBadRequestException;
import com.sfuit.Auth.exceptions.EtResourceNotFoundException;
import com.sfuit.Auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.regex.Pattern;

@Service
@Transactional // if the methods within this class are called, either commits or rollback
public class UserServiceImplement implements UserService{

    @Autowired
    UserRepository userRepository;

    @Override
    public User validateUser(String email, String password) throws EtAuthException
    {
        if(email != null) email = email.toLowerCase();
        return userRepository.findByEmailandPassword(email, password);
    }

    @Override
    public User updateUserPassword(String email, String password) {
        if(email != null) email = email.toLowerCase();
        return userRepository.updateUserPassword(email, password);
    }

    @Override
    public User registerUser(String name, String email, String dob, String phone, String password, String otp, String token, String is_verified, String device_id, String device_token, String fpverified_otp) throws EtAuthException {

        Pattern pattern = Pattern.compile("^(.+)@(.+)$");
        Pattern phone_pattern = Pattern.compile("^?[5-9][0-9]{9}$");
        if(email != null) email = email.toLowerCase();
        if(!pattern.matcher(email).matches())
            throw new EtAuthException("Invalid email format");
        if(!phone_pattern.matcher(phone).matches())
            throw new EtAuthException("Invalid phone number format");
        //Now, checking whether is already present in db or not,
        //for that, we are using getCountByEMail method declared in repo
        //if count> 0, email exists, cannot register again

        Integer count_email = userRepository.getCountByEmail(email);
        Integer count_phone = userRepository.getCountByPhone(phone);


        if(count_email>0)
            throw new EtAuthException("Email already in use");
        if(count_phone>0)
            throw new EtAuthException("Phone number already in use");
        Integer userId = userRepository.create(name, email, dob, phone, password, otp, token, is_verified, device_id, device_token, fpverified_otp);
        return userRepository.findById(userId);
    }

    @Override
    public User verifyUser(String email, String otp) {
        if(email != null) email = email.toLowerCase();
        return userRepository.findByEmailandOTP(email, otp);
    }

    @Override
    public User verifyForgotPassOtp(String email, String otp) {
        if(email != null) email = email.toLowerCase();
        return userRepository.forgotPasswordOtpVerificaiton(email, otp);
    }


    @Override
    public Token addToken(String email, String token, String device_id) {

        if(email != null) email = email.toLowerCase();

        Integer tokenId = userRepository.addUpdatedToken(email, token, device_id);
        return userRepository.findByEmail(email);
    }

    @Override
    public User putDeviceToken(String email, String device_token) throws EtResourceNotFoundException {

        if(email == null)
            throw new EtResourceNotFoundException("Email cant be empty");
            email = email.toLowerCase();
        if(device_token == null)
            throw new EtResourceNotFoundException("Device_token cant be empty");
        return userRepository.findByEmailandUpdateDeviceToken(email, device_token);
    }

    @Override
    public User updateUser(String email, String otp) {
        if(email != null) email = email.toLowerCase();
        return userRepository.findByEmailandUpdateOTP(email, otp);
    }

}
