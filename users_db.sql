drop database d69h2c000l07ls;
drop user savyalwbdjcnnn;
create user savyalwbdjcnnn with password 'fe233606cd82ba0266f78734be758b8d6a8a019db8de8ed17b3232bdaee7c497';
create database d69h2c000l07ls with template=template0 owner=savyalwbdjcnnn;
\connect d69h2c000l07ls;
alter default privileges grant all on tables to savyalwbdjcnnn;
alter default privileges grant all on sequences to savyalwbdjcnnn;


create table sfuit_devices(
device_num integer primary key not null,
device_id varchar(30)  not null,
sensors varchar(2000) not null,
device_isverified varchar(5) not null
);

create table sfuit_users(
user_id integer primary key not null,
name varchar(20) not null,
email varchar(30) not null,
dob varchar(30) not null,
phone varchar(20) not null,
password text not null,
otp varchar(6),
token text not null,
is_verified varchar(10),
device_id varchar(30) not null,
device_token text
);


create table sfuit_token(
token_id integer primary key not null,
email varchar(30) not null,
updated_token text not null,
device_id varchar(30) not null
);

create table sfuit_notifications(
notification_id integer primary key not null,
user_id integer not null,
title varchar(30) not null,
notification_body text not null,
time_stamp timestamp not null,
notification_type varchar(20) not null);
alter table sfuit_notifications add constraint notifications_users_fk
foreign key(user_id) references sfuit_users(user_id);



create sequence sfuit_devices_seq increment 1 start 9000;
create sequence sfuit_users_seq increment 1 start 1;
create sequence sfuit_token_seq increment 1 start 1;
create sequence sfuit_notifications_seq increment 1 start 8000;
