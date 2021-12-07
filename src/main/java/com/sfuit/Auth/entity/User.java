package com.sfuit.Auth.entity;

public class User {

    private Integer userId;
    private String name;
    private String email;
    private String dob;
    private String phone;
    private String password;
    private String otp;
    private String token;
    private String is_verified;
    private String device_id;
    private String device_token;
    private String fpverified_otp;

    public User(Integer userId, String name, String email, String dob, String phone, String password, String otp, String token, String is_verified, String device_id, String device_token, String fpverified_otp) {
        this.userId = userId;
        this.name = name;
        this.email = email;
        this.dob = dob;
        this.phone = phone;
        this.password = password;
        this.otp = otp;
        this.token = token;
        this.is_verified = is_verified;
        this.device_id = device_id;
        this.device_token = device_token;
        this.fpverified_otp = fpverified_otp;
    }

    public String getFpverified_otp() {
        return fpverified_otp;
    }

    public void setFpverified_otp(String fpverified_otp) {
        this.fpverified_otp = fpverified_otp;
    }

    public String getDevice_token() {
        return device_token;
    }

    public void setDevice_token(String device_token) {
        this.device_token = device_token;
    }

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public String getDevice_id() {
        return device_id;
    }

    public void setDevice_id(String device_id) {
        this.device_id = device_id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String password) {
        this.token = password;
    }

    public String getDob() {
        return dob;
    }

    public void setDob(String dob) {
        this.dob = dob;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getOtp() {
        return otp;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }

    public String getIs_verified() {
        return is_verified;
    }

    public void setIs_verified(String is_verified) {
        this.is_verified = is_verified;
    }
}
