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

#include <sql_class.h>
/*
#include <key.h>
#include <records.h>
*/
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
  `counter` int(11) NOT NULL DEFAULT '0' COMMENT 'hotp counter',
  `counter_time_skew` tinyint(4) NOT NULL DEFAULT '0' COMMENT 'totp/hotp password skew, try others password time;time-30;time+30;etc, should not be big or possible DoS',
  `brute_force_max` int(11) NOT NULL DEFAULT '0' COMMENT 'max brute force counter',
  `brute_force_timeout` double NOT NULL DEFAULT '0' COMMENT 'how many seconds should wait after brute force detection',
  `one_access` enum('Y','N') NOT NULL DEFAULT 'N' COMMENT 'ONLY ALLOW ONE ACCESS PER OTP PASSWORD (TOTP)',
  `last_used_counter` bigint(20) NOT NULL DEFAULT '0' COMMENT 'last used counter',
  `last_used_time` double NOT NULL DEFAULT '0' COMMENT 'last used time',
  `brute_force_counter` int(11) NOT NULL DEFAULT '0' COMMENT 'current brute force counter, change to 0 to remove current brute force block',
  `brute_force_block_time` bigint(20) NOT NULL DEFAULT '0' COMMENT 'next allowed login after brute force detected, change to 0 to remove current brute force block',
  `wellknown_passwords` text NOT NULL COMMENT 'wellknow password separated by ";" character',
  PRIMARY KEY (`Host`,`User`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8

*/

/* Name of table where OTP information resides */
const LEX_STRING db_name = {C_STRING_WITH_LEN("mysql")};
const LEX_STRING table_name = {C_STRING_WITH_LEN("otp_user")};

/* STRUCTS / ENUMS */

enum otp_user_columns{
  HOST,
  USER,
  OTP_TYPE,
  SECRET,
  TIME_STEP,
  COUNTER,
  COUNTER_TIME_SKEW,
  BRUTE_FORCE_MAX,
  BRUTE_FORCE_TIMEOUT,
  ONE_ACCESS_ENUM,
  LAST_USED_COUNTER,
  LAST_USED_TIME,
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
  unsigned int counter;		/* hotp counter */
  unsigned int ct_skew;		/* ct retries with different values (allow time sync) */
  unsigned int bf_max;		/* bf max counter */
  double bf_timeout;		/* seconds to lock user login */
  bool one_access;		/* true/false if we only allow one connection per otp  */
  unsigned int last_counter;	
  double last_time;		/* unix time stamp */
  double last_access;		/* unix time stamp */
  unsigned int bf_count;
  unsigned int bf_block_time;	/* unix time stamp */
  char *wellknown_passwords;	/* must check how to create a list of passwords separated by ";" */
  
  bool changed;		        /* true = must update table */
  unsigned int calc_counter;	/* used to calculate hotp */
  double calc_time;		/* used to calculate totp */
};
/* PLUGIN FUNCTIONS */

/* helper function to read otp row */
bool read_otp_table(const char *host, unsigned int host_len,
                    const char *user, unsigned int user_len,
                    struct otp_user_info *uinfo){ 
  /* return false/true, false = no login, maybe otp table don't exists? */
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
  return TRUE;
}
/* helper functino to write otp row */
bool write_otp_table(const char *host,unsigned int host_len,
                     const char *user,unsigned int user_len,
                     struct otp_user_info *uinfo){	
/* return false/true, false = error while writing to table */
  // open table
  //   return false if error (table not found)
  // find host/user record
  //   return false if not found
  // write record
  // close table
  // return true
}
bool create_userotp_from_string(const char *host,unsigned int host_len,
                                const char *user,unsigned int user_len,
                                const char *auth_string){
}
/* helper function to check if we found a well known password, and if found remove it from list and return true */
bool check_and_update_wkn_password(unsigned char *password,struct otp_user_info *uinfo){/* return false/true, false = no password match, update the structure if found, removing the password */
  // interact wkn password list (maybe a hash index?)
  // if not found, return false
  // remove wkn password from list
  // mark otp_structure as changed
  // return true
}
/* helper function to increase brute force counter */
void brute_force_incr(struct otp_user_info* otp_row){
  // check if we will not overflow
  if(otp_row->bf_count<otp_row->bf_max){
    otp_row->bf_count++;	/* possible problem with overflow ? */
    otp_row->changed=TRUE;
  }
}
/* helper function to reset brute force counter */
void brute_force_reset(struct otp_user_info* otp_row){
  otp_row->bf_count=0;
  otp_row->bf_block_time=0;
  otp_row->changed=TRUE;
}
/* helper function to sync calc time/counter to table counter */
void sync_otp_counter_time(struct otp_user_info* otp_row){
  otp_row->counter=otp_row->calc_counter;
  otp_row->changed=TRUE;
}
/* helper function to sync last access */
void sync_last_access(struct otp_user_info* otp_row){
  my_hrtime_t now= my_hrtime();	/* unix time stamp from current time */
  otp_row->last_access=now.val;
  otp_row->changed=TRUE;
}
/* helper function to bf block */
void bf_block(struct otp_user_info* otp_row){
  my_hrtime_t now= my_hrtime();	/* unix time stamp from current time */
  otp_row->bf_block_time=now.val + otp_row->bf_timeout;
  otp_row->changed=TRUE;
}
/* helper function to calculate time value */
double calc_time(double time,unsigned int skew,unsigned int time_step){
  // skew % 2 = 0 => add to initial time
  // skew % 2 = 1 => sub from initial time
  // skew =0 return time/time_step
  double ret=0;
  ret=floor(time / time_step) * time_step;
  if(skew==0) return ret;
  if(skew % 2 == 0){
    ret=ret + (skew>>1)*time_step;
  }else{
    ret=ret - (skew>>1)*time_step;
  }
  return ret;
}
/* helper function to calculate counter value */
unsigned int calc_counter(unsigned int cur,unsigned int skew){
  // skew % 2 = 0 => add to initial counter
  // skew % 2 = 1 => sub from initial counter
  // skew =0 return counter
  if(skew==0) return cur;
  unsigned int ret=0;
  if(skew % 2 == 0){
    ret=cur + (skew>>1);
  }else{
    ret=cur - (skew>>1);
  }
  return ret;
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
  if(otp_row->otp_type==TOTP)
    return create_totp(otp_row,otp_password);
  if(otp_row->otp_type==HOTP)
    return create_totp(otp_row,otp_password);
//  if(otp_row.otp_type==SKEY)
//    return create_skey(otp_row,otp_password);
  return FALSE;
}

/* MYSQL AUTH PLUGIN FUNCTIONS */
static int otp_auth_interface(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  THD* thd;
/*
the structure...

1) get information from otp table
2) check brute force
3) restart brute force after timeout
4) ask user password / otp password
5) increase brute force if bad password (or error)
6) check wellknown password
6.1) remove used wellknown password
6.2) save structure and accept login
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
	
/* START OF DIALOG */
  unsigned char *pkt;
  int pkt_len;
  my_hrtime_t now= my_hrtime();	/* unix time stamp from current time */
  otp_user_info otp_row;

  const char *user = info->user_name;
  unsigned int user_len = info->user_name_length;
  const char *host = info->host_or_ip;
  unsigned int host_len = info->host_or_ip_length;
  
  /* 1)get information from otp table  */
  if(read_otp_table(host,host_len,user,user_len,&otp_row)!=TRUE){
    // create from auth string ?
    if(create_userotp_from_string(host,host_len,user,user_len,info->auth_string)!=TRUE)
      return CR_ERROR; /* sorry */
  }
  
  /* 2) check brute force */
  if(otp_row.bf_max>0 && otp_row.bf_count>=otp_row.bf_max){
    if(otp_row.bf_block_time>now.val)
      return CR_ERROR; /* sorry */
    /* 3) restart brute force after timeout */
    brute_force_reset(&otp_row);
  }
  
  /* 4) ask user password / otp password */
  if (vio->write_packet(vio,
                        (const unsigned char *) PASSWORD_QUESTION "Password, please:",
                        18)){
    /* 5) increase brute force if bad password */
    brute_force_incr(&otp_row);
    write_otp_table(host,host_len,user,user_len,&otp_row);
    return CR_ERROR;
  }

  /* read the answer */
  if ((pkt_len= vio->read_packet(vio, &pkt)) < 0){
    /* 5) increase brute force if bad password */
    brute_force_incr(&otp_row);
    write_otp_table(host,host_len,user,user_len,&otp_row);
    return CR_ERROR;
  }
  info->password_used= PASSWORD_USED_YES;

  /* CHECK USER PASSWORD (mysql.user table) */
  if (strcmp((const char *) pkt, info->auth_string)){
    /* 5) increase brute force if bad password */
    brute_force_incr(&otp_row);
    write_otp_table(host,host_len,user,user_len,&otp_row);
    return CR_ERROR;
  }

  /* REQUEST OTP PASSWORD */
  if (vio->write_packet(vio,
                        (const unsigned char *) LAST_QUESTION "OTP:", /* INCLUDE OTP TYPE? */
                        5)){
    /* 5) increase brute force if bad password */
    brute_force_incr(&otp_row);
    write_otp_table(host,host_len,user,user_len,&otp_row);
    return CR_ERROR;
  }

  /* read the answer */
  if ((pkt_len= vio->read_packet(vio, &pkt)) < 0){
    /* 5) increase brute force if bad password */
    brute_force_incr(&otp_row);
    write_otp_table(host,host_len,user,user_len,&otp_row);
    return CR_ERROR;
  }
/* END OF DIALOG */
  
  
  /* 6) check wellknown password */
  if(check_and_update_wkn_password(pkt,&otp_row)){
    /* 6.2) save structure and accept login */
    brute_force_reset(&otp_row);
    write_otp_table(host,host_len,user,user_len,&otp_row);
    return CR_OK;
  }
  

  /* 7) save startup time and counter (memory only) */
  unsigned int cur_skew=0;
  char* current_otp_password;	/* current password */
  
  
  
  while(1){
    /* 8) start a skew while loop (even with skew=0) */
    /* update calc counter with new skew value, based at startup counter + current skew */
    otp_row.calc_counter=calc_counter(otp_row.counter,cur_skew);
    /* update calc time with new skew value, based at startup time + current skew */
    otp_row.calc_time=calc_time(now.val,cur_skew,otp_row.time_step);
    cur_skew++;
    /* 9) create otp using current counter/time */
    create_user_otp(&otp_row,current_otp_password);
    
    /* 10) check created otp with user otp */
    if (strcmp((const char *) pkt, current_otp_password)){
      /* 10.1) if ok check only one login otp */
      if (otp_row.one_access==FALSE){
        /* 10.3) accept login if match and one login is ok, or one login is off */
        brute_force_reset(&otp_row);
	/* sync current calc counter */
	sync_otp_counter_time(&otp_row);
        write_otp_table(host,host_len,user,user_len,&otp_row);
        return CR_OK;
      }else if (otp_row.otp_type==TOTP && otp_row.last_time==otp_row.calc_time){
        /* 10.3) accept login if match and one login is ok, or one login is off */
        brute_force_reset(&otp_row);
	/* sync current calc counter */
	sync_otp_counter_time(&otp_row);
        write_otp_table(host,host_len,user,user_len,&otp_row);
        return CR_OK;
      }else if (otp_row.otp_type==HOTP && otp_row.last_counter==otp_row.calc_counter){
        /* 10.3) accept login if match and one login is ok, or one login is off */
        brute_force_reset(&otp_row);
	/* sync current calc counter */
	sync_otp_counter_time(&otp_row);
        write_otp_table(host,host_len,user,user_len,&otp_row);
        return CR_OK;
      }
      /* 10.2) increase brute force counter if not match */
      brute_force_incr(&otp_row);
      write_otp_table(host,host_len,user,user_len,&otp_row);
      return CR_ERROR;
    }
    
    /* 11) if we have skew, increase counter based at current skew counter + startup time/counter */
    if(cur_skew>otp_row.ct_skew){ /* must check how TOTP/HOTP/SKEY do, there's a RFC */
      /* 11.1) check if we got max skew, if not  start loop again (8)  */
      continue;
    }
    /* 12) if we don't have a otp match, and we got max of skew counter, we got a bad password, increase brute force counter */
    brute_force_incr(&otp_row);
    write_otp_table(host,host_len,user,user_len,&otp_row);
    return CR_ERROR;
  }
  /* should never be here */
  return CR_ERROR;
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
    if (args->arg_count > 2) {
        strmov(message,"Usage: GET_OTP( <host> , <user_name> )");
        return 1;
    }
    if (args->arg_count == 2) {
        // one specific user
	/* check permission (GRANT level ) */
      // if (check_global_access(thd, PROCESS_ACL, true))
          return 1; /* error */
    } else {
	// current user OTP 
	/* how to get current user? */
    }
    return 0;
}
void GET_OTP_deinit(UDF_INIT *initid) {
    if (initid->ptr)
        free(initid->ptr);
}

/* Return NULL if can't get a OTP */
char *GET_OTP(UDF_INIT *initid, UDF_ARGS *args, char *result,
               unsigned long *length, char *is_null, char *error) {
    /* with the current user information, return the current OTP password using create_user_otp() function; */
    my_hrtime_t now= my_hrtime();	/* unix time stamp from current time */
    char *otp_password;
    struct otp_user_info otp_row;
    /*
    if(read_otp_table(args->args[0],args->args[1],&otp_row)!=TRUE){
	*is_null = 1;
	return 0;
        }*/
    otp_row.calc_counter=otp_row.counter;
    otp_row.calc_time=calc_time(now.val,0,otp_row.time_step);
    //    create_user_otp(struct otp_user_info* otp_row,char* otp_password);
    
    *length = (unsigned long)strlen(otp_password);
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

