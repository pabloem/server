/* Copyright (C) 2014 Roberto Spadim - Spaempresarial Brazil

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; version 2 of the
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA */

// based at dialog_example.c example file
/* INCLUDES */    
#include <mysql/plugin_auth.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mysql/auth_dialog_client.h>

/* MYSQL SCHEMA TABLE STRUCTURE */
/*
CREATE TABLE `otp_user` (
  `Host` varchar(60) NOT NULL DEFAULT '' COMMENT 'same value of host column of mysql.user',
  `User` varchar(16) NOT NULL DEFAULT '' COMMENT 'same value of user column of mysql.user',
  `otp_type` enum('TOTP','HOTP') NOT NULL DEFAULT 'TOTP' COMMENT 'OTP TYPE',
  `secret` varchar(255) NOT NULL DEFAULT '' COMMENT 'otp password, each otp_type have a format',
  `time_step` int(11) NOT NULL DEFAULT '0' COMMENT 'totp time slice, floor(time/time_step)*time_step',
  `counter_time_skew` tinyint(4) NOT NULL DEFAULT '0' COMMENT 'totp/hotp password skew, try others password time;time-30;time+30;etc, should not be big or possible DoS',
  `brute_force_max` int(11) NOT NULL DEFAULT '0' COMMENT 'max brute force counter',
  `brute_force_timeout` double NOT NULL DEFAULT '0' COMMENT 'how many seconds should wait after brute force detection',
  `one_access` enum('Y','N') NOT NULL DEFAULT 'N' COMMENT 'ONLY ALLOW ONE ACCESS PER OTP PASSWORD (TOTP)',
  `last_used_otp` bigint(20) NOT NULL DEFAULT '0' COMMENT 'last used otp (time in seconds or counter), use bigint since we can use >2039 year value',
  `brute_force_counter` int(11) NOT NULL DEFAULT '0' COMMENT 'current brute force counter, change to 0 to remove current brute force block',
  `brute_force_block_time` bigint(20) NOT NULL DEFAULT '0' COMMENT 'next allowed login after brute force detected, change to 0 to remove current brute force block',
  `wellknown_passwords` text NOT NULL COMMENT 'wellknow password separated by ";" character',
  PRIMARY KEY (`Host`,`User`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8

*/

/* Name of table where OTP information resides */
const LEX_STRING db_name = {C_STRING_WITH_LEN("mysql")}
const LEX_STRING table_name = {C_STRING_WITH_LEN("otp_user")}

/* STRUCTS / ENUMS */

enum otp_user_columns{
  HOST,
  USER,
  OTP_TYPE,
  SECRET,
  TIME_STEP,
  COUNTER_TIME_SKEW,
  BRUTE_FORCE_MAX,
  BRUTE_FORCE_TIMEOUT,
  ONE_ACCESS_ENUM,
  LAST_USED_OTP,
  BRUTE_FORCE_COUNTER,
  BRUTE_FORCE_BLOCK_TIME,
  WELLKNOWN_PASSWORDS
};

enum otp_type{
  TOTP,
  HOTP
};

/* sufix:
   ct = counter and/or time 
   bg = brute force
*/
struct otp_user_info{	
  enum otp_type otp_type;	/* totp or hotp */
  char *secret;			/* secreat text, normally a base32 value */
  unsigned int time_step;	/* time step, for example a new otp each 30 seconds */
  unsigned int ct_skew;		/* ct retries with different values (allow time sync) */
  unsigned int bf_max;		/* bf max counter */
  double bf_timeout;		/* seconds to lock user login */
  bool one_access;		/* true/false if we only allow one connection per otp  */
  double last_access;		/* unix time stamp */
  unsigned int bf_count;	/* 
  unsigned int bg_block_time;	/* unix time stamp */
  char *wellknown_passwords;	/* must check how to create a list of passwords separated by ";" */
  bool struct_changed;		/* true = must update table */
};
/* PLUGIN FUNCTIONS */


/* TODO: 
   IMPLEMENT TOTP PASSWORD GENERATOR FUNCTION (GENERATE A PASSWORD WITH TIME+KEY+TIME_STEP)
   IMPLEMENT HOTP PASSWORD GENERATOR FUNCTION (GENERATE A PASSWORD WITH COUNTER+KEY)
   IMPLEMENT S/KEY PASSWORD - SAME AS HOTP BUT USING S/KEY LOGIC
*/
bool read_otp_table(host,user,otp_structure){		/* return false/true, false = no login, maybe otp table don't exists? */
  // open table
  //   return false if error (table not found)
  // get host/user record
  //   return false if not found
  // read record
  // close table
  
  // change record values to otp struct
  // remove overflows / use currect limits (to avoid bf counter overflow for example)
  // create a list of well known password
  
  // return true
}
bool write_otp_table(host,user,otp_structure){		/* return false/true, false = error while writing to table */
  // open table
  //   return false if error (table not found)
  // find host/user record
  //   return false if not found
  // write record
  // close table
  // return true
}
bool check_and_update_wkn_password(password,otp_structure){/* return false/true, false = no password match, update the structure if found, removing the password */
  // interact wkn password list (maybe a hash index?)
  // if not found, return false
  // remove wkn password from list
  // mark otp_structure as changed
  // return true
}
void brute_force_incr(otp_user_info* otp_row){
  // check if we will not overflow
  if(otp_row.bf_count<otp_row.bf_max){
    otp_row.bf_count++;	/* possible problem with overflow ? */
    otp_row.changed=TRUE;
  }
}
void brute_force_reset(otp_user_info* otp_row){
  otp_row.bf_count=0;
  otp_row.bg_block_time=0;
  otp_row.changed=TRUE;
}

bool create_totp(otp_user_info* otp_row,char* otp_password){ /* 	http://www.nongnu.org/oath-toolkit/ */
  // get shared secret
  // convert from base32 to totp base
  //   if wrong base or blank secret, or any other erro -> return false
  // create totp
  // return true
}
bool create_hotp(otp_user_info* otp_row,char* otp_password){ /* 	http://www.nongnu.org/oath-toolkit/ */
  // get shared secret
  // convert from base32 to hotp base
  //   if wrong base or blank secret, or any other erro -> return false
  // create hotp
  // return true
}
bool create_skey(otp_user_info* otp_row,char* otp_password){ /* 	ftp://ftp.ntua.gr/mirror/skey/skey/
				http://0x9900.com/blog/2013/08/28/two-factor-authentication-with-ssh-&-s/key-on-openbsd/ */
  // get shared secret
  // if wrong secret or blank secret, or any other erro -> return false
  // create skey
  // return true
}
bool create_user_otp(otp_user_info* otp_row,char* otp_password){ 
			/*	receive user otp table row and select what key should be used 
				https://code.google.com/p/google-authenticator/source/browse/#git%2Flibpam */
  if(otp_row.otp_type==TOTP)
    return create_totp(otp_row,otp_password);
  if(otp_row.otp_type==HOTP)
    return create_totp(otp_row,otp_password);
//  if(otp_row.otp_type==SKEY)
//    return create_skey(otp_row,otp_password);
  return FALSE;
}

/* MYSQL AUTH PLUGIN FUNCTIONS */
static int otp_auth_interface(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
/*
the structure...

1) get information from otp table   
2) check brute force
3) restart brute force after timeout
4) ask user password / otp password
5) increase brute force if bad password
6) check wellknown password
6.1) remove used wellknown password
7) save startup time and counter (memory only)
8) start a skew while loop (even with skew=0)
9) create otp using current counter/time
10) check created otp with user otp
10.1) if ok check only one login otp
10.2) increase brute force counter if not match
10.3) accept login if match and one login is ok, or one login is off
11) if we have skew, increase counter based at current skew counter + startup time/counter
11.1) check if we got max skew, if not  start loop again (8) 
12) if we don't have a otp match, and we got max of skew counter, we got a bad password, increase brute force counter

13) end =] source should not get here, since the while loop don't have a end, the end is: skew counter = max skew value from user table (check that we need a max value or we can get a DoS with very big values, i think a tinyint is ok)


*/	
	
	
  unsigned char *pkt;
  int pkt_len;
  my_hrtime_t startup_time= my_hrtime();	/* unix time stamp from current time */
  otp_user_info otp_row;
  
  /* 1)get information from otp table  */
  read_otp_table(host,user,otp_row);
  
  /* 2) check brute force */
  if(otp_row.bf_max>0 && otp_row.bf_count>=otp_row.bf_max){
    if(otp_row.bg_block_time>startup_time.val)
      return CR_ERROR; /* sorry */
    brute_force_reset(otp_row);
  }
  
  /* send a password question */
  if (vio->write_packet(vio,
                        (const unsigned char *) PASSWORD_QUESTION "Password, please:",
                        18)){
    brute_force_incr(otp_row);
    write_otp_table();
    return CR_ERROR;
  }

  /* read the answer */
  if ((pkt_len= vio->read_packet(vio, &pkt)) < 0){
    brute_force_incr(otp_row);
    write_otp_table();
    return CR_ERROR;
  }
  info->password_used= PASSWORD_USED_YES;

  /* fail if the password is wrong */
  // check with mysql.users table
  if (strcmp((const char *) pkt, info->auth_string)){
    brute_force_incr(otp_row);
    write_otp_table();
    return CR_ERROR;
  }

  /* send otp question */
  if (vio->write_packet(vio,
                        (const unsigned char *) LAST_QUESTION "OTP:", /* INCLUDE OTP TYPE? */
                        5)){
    brute_force_incr(otp_row);	/* ?increase brute force counter? */
    write_otp_table();		/* must save if we reseted bf at startup */
    return CR_ERROR;
  }

  /* read the answer */
  if ((pkt_len= vio->read_packet(vio, &pkt)) < 0){
    brute_force_incr(otp_row);
    write_otp_table();
    return CR_ERROR;
  }

  /* check the reply */

  /* implement well known password check ?*/
  if(check_and_update_wkn_password(pkt,otp_structure)){
    /*login ok*/
    brute_force_reset(otp_row);
    write_otp_table();
    return CR_OK;
  }
  

  
  /* now =>   my_hrtime_t qc_info_now= my_hrtime();   qc_info_now.val  = unix timestamp */
  
  startup_time.val
  current_counter=startup_counter=get_from_otp_table;
  while(1){
    // (1) CHECK IF OTP IS OK
    current_otp_password = create_otp_password(
    	otp_information,
    	current_time,
    	current_counter
    	);
    if (strcmp((const char *) pkt, current_otp_password)){
      // (2) OK AND ONLY ONE LOGIN, CHECK LAST OTP = CURRENT OTP => (LOGIN)
      // (3) IF OK AND NO ONLY ONE LOGIN => (LOGIN)
      if ((one login == 'y' && last_otp_counter_timer==current_otp_counter_time) ||
           one login != 'y'){
        /*login ok*/
        reset_brute_force_counter();
        sync_counter (if using counter_time_skew)
        // (LOGIN) SYNC COUNTER IF USING SKEY/HOTP
        return CR_OK;
      }else if (one login == 'y'){
        increase_brute_force_counter();
        return CR_ERROR;
      }
    }
    // (4) WRONG OTP CHECK IF WE SHOULD TRY AGAIN WITH TIME SKEW OR COUNTER SKEW (COUNTER_TIME_SKEW) IF TRUE, TRY AGAIN (1)
    if(counter_time_skew>0){ /* must check how TOTP/HOTP/SKEY do, there's a RFC */
      change_current_time_counter to a value before or after the startup_time/startup_counter;
      continue; /*try again*/
    }
    // (5) WRONG OTP, INCREMENT BRUTE FORCE ATTACK COUNTER => DON'T ALLOW LOGIN
    // sorry :(
    increase_brute_force_counter();
    return CR_ERROR;
  }
}

static struct st_mysql_auth otp_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "dialog", /* requires dialog client plugin */
  otp_auth_interface
};



/* MYSQL UDF FUNCTIONS */
/* 
	TODO: include a function to test OTP, 
	for example SELECT GET_OTP('USER') 
	this will allow admin to create user and check if current OTP is ok or not 
	before allowing user to login and start brute force counter
*/
my_bool GET_OTP_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count > 1) {
        strmov(message,"Usage: GET_OTP( <user_name> )"); /* use same primary key as otp table */
        return 1;
    }
    if (args->arg_count == 1) {
        // one specific user OTP
	check permission (GRANT);
        args->arg_type[0] = STRING_RESULT;
    } else {
	// current user OTP 
	/*use the current username*/
    }
/*
    if ( !(initid->ptr = 
        (char *) malloc( sizeof(char) * MAX_IMAGE_SIZE ) ) ) {
        strmov(message, "Couldn't allocate memory!");
        return 1;
    }
    bzero( initid->ptr, sizeof(char) * MAX_IMAGE_SIZE );
*/
    return 0;
}
void GET_OTP_deinit(UDF_INIT *initid) {
    if (initid->ptr)
        free(initid->ptr);
}

/* Return NULL if can't get a OTP */
char *GET_OTP(UDF_INIT *initid, UDF_ARGS *args, char *result,
               unsigned long *length, char *is_null, char *error) {
/*
	strncpy( filename, args->args[0], args->lengths[0] );

	*is_null = 1;	
        return 0;
*/
    with the current user information, return the current OTP password using create_user_otp() function;

    *length = (unsigned long)some_size;
    return initid->ptr;
}


/********************* DECLARATIONS ****************************************/

mysql_declare_plugin(dialog)
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &otp_handler,
  "otp_auth",
  "Roberto Spadim - Spaempresarial Brazil",
  "Dialog otp auth plugin",
  PLUGIN_LICENSE_GPL,
  NULL,
  NULL,
  0x0100,
  NULL,
  NULL,
  NULL,
  0,
}mysql_declare_plugin_end;

