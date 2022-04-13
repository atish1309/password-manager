CREATE DATABASE IF NOT EXISTS passVault;
USE passVault;
CREATE TABLE IF NOT EXISTS secretKey(id INTEGER PRIMARY KEY, skey TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);


CREATE TABLE IF NOT EXISTS encryptedPassword(
username VARCHAR(20) PRIMARY KEY,
userPassword TEXT NOT NULL);


CREATE TABLE IF NOT EXISTS vault(
username VARCHAR(20) NOT NULL,
platform TEXT NOT NULL,
account TEXT NOT NULL,
password TEXT NOT NULL,
memo TEXT NULL,
FOREIGN KEY (username) REFERENCES encryptedPassword(username),
PRIMARY KEY (username,account(20),platform(20)));




/*
As our project is a password manager, most of the updates and inserts done are in encrypted form 
and are handled by the program itself. These are the formats of the statements used, where the %s 
refer to a string variable being used.

INSERT INTO masterpassword(id,password) VALUES(1,%s)
SELECT * FROM masterpassword
SELECT * FROM encryptedPassword WHERE username=(%s)
UPDATE encryptedPassword SET userPassword=(%s) WHERE username=(%s)
SELECT * FROM vault WHERE username=(%s)
INSERT INTO encryptedPassword(username,userPassword) VALUES(%s,%s)
SELECT * FROM vault WHERE username=(%s) AND platform=(%s) AND account=(%s)
INSERT INTO vault(username,platform,account,password,memo) VALUES(%s,%s,%s,%s,%s) 
DELETE FROM vault WHERE username=(%s) AND platform=(%s) AND account=(%s)
UPDATE vault SET password=(%s) WHERE username=(%s) and platform=(%s) and account=(%s)
SELECT memo FROM vault WHERE username = (%s) and account = (%s) and platform = (%s)
UPDATE vault SET memo = (%s) WHERE username = (%s) and account = (%s) and platform = (%s)

/* These are some testcases for verifying the working of the program*/
INSERT INTO `secretkey` (`id`,`skey`) VALUES (1,'70db37760ce74b7fa42ffc68e83b9d93');
INSERT INTO `masterpassword` (`id`,`password`) VALUES (1,'6EVf');
INSERT INTO `encryptedpassword` (`username`,`userPassword`) VALUES ('Ankit_Gupta1309','¹ýò°Ö(!');
INSERT INTO `encryptedpassword` (`username`,`userPassword`) VALUES ('Mark_Hamill_the_best','¸èýå~tz>\Zy');
INSERT INTO `vault` (`username`,`platform`,`account`,`password`,`memo`) VALUES ('Ankit_Gupta1309','Twitter','Ankit_G','*ñÿê&÷»¬=','Hello, this is Ankit\'s Twitter Account.\n');
INSERT INTO `vault` (`username`,`platform`,`account`,`password`,`memo`) VALUES ('Ankit_Gupta1309','Reddit','Gupta_Ankit','0ìíè$çÇ¿¥?','This is Ankit\'s Reddit Account\n');
INSERT INTO `vault` (`username`,`platform`,`account`,`password`,`memo`) VALUES ('Mark_Hamill_the_best','Instagram','Hamill_Sky','Jîä¶¯1éÓ','Hamil\'s Instagram\n');
INSERT INTO `vault` (`username`,`platform`,`account`,`password`,`memo`) VALUES ('Mark_Hamill_the_best','Facebook','Mark Hamill','²Mýé¢¶!©RÖèÚ','Hamill\'s Facebook\n');



/*The corresponding non encrypted passwords are
Master Password: Administrator


Username: Ankit_Gupta1309
userPassword: angc1234

Platforms:
	Username: Ankit_G
	Platform: Twitter
	Platform_Pass: knowledge6808
	
	Username: Gupta_Ankit
	Platform: Reddit
	Platform_Pass: strength1212

Username: Mark_Hamill_the_best
userPassword: worldpeace1234

Platforms:
	Username: Hamill_Sky
	Platform: Instagram
	Platform_Pass: Highsky4545

	Username: Mark Hamill
	Platform: Facebook
	Platform_Pass: integrity1155

*/


/*
After using the program, please use the below to verify
*/

SELECT * from secretKey;
SELECT * from masterpassword;
SELECT * from encryptedPassword;
SELECT * from vault;


/*
DROP TABLE vault;
DROP TABLE encryptedPassword;
DROP TABLE masterpassword;
DROP TABLE secretKey;
DROP DATABASE passVault;
*/