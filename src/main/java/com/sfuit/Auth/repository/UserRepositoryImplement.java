package com.sfuit.Auth.repository;

import com.sfuit.Auth.entity.Token;
import com.sfuit.Auth.entity.User;
import com.sfuit.Auth.exceptions.EtAuthException;
import com.sfuit.Auth.exceptions.EtResourceNotFoundException;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.sql.Statement;

@Repository
public class UserRepositoryImplement implements UserRepository{

    private static final String SQL_CREATE = "INSERT INTO SFUIT_USERS(USER_ID, NAME, EMAIL, DOB, PHONE, PASSWORD, OTP, TOKEN, IS_VERIFIED, DEVICE_ID, DEVICE_TOKEN) VALUES(NEXTVAL('SFUIT_USERS_SEQ'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String SQL_COUNT_BY_EMAIL = "SELECT COUNT(*) FROM SFUIT_USERS WHERE EMAIL = ?";
    private static final String SQL_COUNT_BY_PHONE = "SELECT COUNT(*) FROM SFUIT_USERS WHERE PHONE = ?";
    private static final String SQL_FIND_BY_ID = "SELECT USER_ID, NAME, EMAIL, DOB, PHONE, PASSWORD, OTP, TOKEN, IS_VERIFIED, DEVICE_ID, DEVICE_TOKEN " +
            "FROM SFUIT_USERS WHERE USER_ID = ?";
    private static final String SQL_FIND_BY_EMAIL = "SELECT USER_ID, NAME, EMAIL, DOB, PHONE, PASSWORD, OTP, TOKEN, IS_VERIFIED, DEVICE_ID, DEVICE_TOKEN " +
            "FROM SFUIT_USERS WHERE EMAIL = ?";
    private  static final String SQL_UPDATE_ROW = "UPDATE SFUIT_USERS SET IS_VERIFIED = 'true', OTP = null WHERE EMAIL = ? ";
    private static final String SQL_UPDATE_DEVICES_ROW = "UPDATE SFUIT_DEVICES SET DEVICE_ISVERIFIED = 'true' FROM SFUIT_USERS " +
            "WHERE SFUIT_DEVICES.DEVICE_ID = SFUIT_USERS.DEVICE_ID AND SFUIT_USERS.EMAIL = ?";
    private static final String SQL_CREATE_TOKENROW = "INSERT INTO SFUIT_TOKEN(TOKEN_ID, EMAIL, TOKEN_UPDATED, DEVICE_ID) VALUES(NEXTVAL('SFUIT_TOKEN_SEQ'), ?, ?, ?)";
    private static final String SQL_FIND_BY_EMAIL_TOKEN = "SELECT TOKEN_ID, EMAIL, TOKEN_UPDATED, DEVICE_ID FROM SFUIT_TOKEN WHERE EMAIL = ?";
    private static final String SQL_UPDATE_DEVICE_TOKEN = "UPDATE SFUIT_USERS SET DEVICE_TOKEN = ? WHERE EMAIL = ? ";

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Override
    public Integer create(String name, String email, String dob, String phone, String password, String otp, String token, String is_verified, String device_id, String device_token) throws EtAuthException {
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(10));
        try{
            //for holding key value of id
            KeyHolder keyHolder = new GeneratedKeyHolder();
            //calling jdbc update through lambda and keyholder

            jdbcTemplate.update(connection -> {
                PreparedStatement ps = connection.prepareStatement(SQL_CREATE, Statement.RETURN_GENERATED_KEYS);
                ps.setString(1,name);
                ps.setString(2,email);
                ps.setString(3,dob);
                ps.setString(4,phone);
                ps.setString(5,hashedPassword);
                ps.setString(6,otp);
                ps.setString(7,token);
                ps.setString(8,is_verified);
                ps.setString(9,device_id);
                ps.setString(10,device_token);
                return ps;
            }, keyHolder);
            return (Integer) keyHolder.getKeys().get("USER_ID");
        }catch(Exception e)
        {
            throw new EtAuthException("Invalid details. Failed to create account");
        }
    }

    @Override
    public Integer addUpdatedToken(String email, String token, String device_id) {
        try{
            KeyHolder keyHolder = new GeneratedKeyHolder();

            jdbcTemplate.update(connection -> {
                PreparedStatement ps = connection.prepareStatement(SQL_CREATE_TOKENROW, Statement.RETURN_GENERATED_KEYS);
                ps.setString(1, email);
                ps.setString(2, token);
                ps.setString(3, device_id);
                return ps;
            }, keyHolder);
            return (Integer) keyHolder.getKeys().get("TOKEN_ID");
        }catch (Exception e)
        {
            throw new EtAuthException("JWT Login token is not stored");
        }
    }

    @Override
    public User findByEmailandPassword(String email, String password) throws EtAuthException {
        try{
            User user = jdbcTemplate.queryForObject(SQL_FIND_BY_EMAIL, userRowMapper, new Object[]{email});
            if("true".equals(user.getIs_verified())) {
                if (!BCrypt.checkpw(password, user.getPassword()))
                    throw new EtAuthException("Invalid email/password");
            }
            else
                throw new EtAuthException("Verification failed");
            return user;
        }catch (EmptyResultDataAccessException e) {
            throw new EtAuthException("Invalid email/password");
        }
    }

    @Override
    public Token findByEmail(String email) throws EtAuthException{
            return jdbcTemplate.queryForObject(SQL_FIND_BY_EMAIL_TOKEN, tokenRowMapper, new Object[]{email});
    }

    @Override
    public Integer getCountByEmail(String email) {
        return jdbcTemplate.queryForObject(SQL_COUNT_BY_EMAIL, Integer.class, new Object[]{email});
    }

    @Override
    public User findById(Integer userId) {
        return jdbcTemplate.queryForObject(SQL_FIND_BY_ID, userRowMapper, new Object[]{userId});
    }

    @Override
    public User findByEmailandOTP(String email, String otp) {
        try {
            User user = jdbcTemplate.queryForObject(SQL_FIND_BY_EMAIL, userRowMapper, new Object[]{email});
            if(!otp.equals(user.getOtp()))
                throw new EtAuthException("Invalid email/otp");
            jdbcTemplate.update(SQL_UPDATE_ROW, email);
            jdbcTemplate.update(SQL_UPDATE_DEVICES_ROW, email);
            return user;
        }catch (EmptyResultDataAccessException e){
            throw new EtAuthException("Invalid email/otp");
        }
    }

    @Override
    public User findByEmailandUpdateDeviceToken(String email, String device_token) {

        try {
            User user = jdbcTemplate.queryForObject(SQL_FIND_BY_EMAIL, userRowMapper, new Object[]{email});
            if(!email.equals(user.getEmail()))
                throw new EtResourceNotFoundException("Invalid Email");
            jdbcTemplate.update(SQL_UPDATE_DEVICE_TOKEN, device_token, email);
            return user;
        }catch (EmptyResultDataAccessException e)
        {
            throw new EtResourceNotFoundException("Invalid Email");
        }
    }


    @Override
    public Integer getCountByPhone(String phone) {
        return jdbcTemplate.queryForObject(SQL_COUNT_BY_PHONE, Integer.class, new Object[]{phone});
    }

    private RowMapper<User> userRowMapper = ((rs, rowNum) -> {
        return new User(rs.getInt("USER_ID"),
                        rs.getString("NAME"),
                        rs.getString("EMAIL"),
                        rs.getString("DOB"),
                        rs.getString("PHONE"),
                        rs.getString("PASSWORD"),
                        rs.getString("OTP"),
                        rs.getString("TOKEN"),
                        rs.getString("IS_VERIFIED"),
                        rs.getString("DEVICE_ID"),
                        rs.getString("DEVICE_TOKEN"));
    });

    private RowMapper<Token> tokenRowMapper = ((rs, rowNum) -> {
        return new Token(rs.getInt("TOKEN_ID"),
                         rs.getString("EMAIL"),
                         rs.getString("UPDATED_TOKEN"),
                         rs.getString("DEVICE_ID"));
    });
}
