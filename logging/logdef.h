/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/

#ifndef __LOGDEF_H__
#define __LOGDEF_H__

#define LOCAL_ZLOGCONFIG_PATH "conf_examples/zlog.conf"
#define DEFAULT_ZLOGCONFIG_PATH "conf_examples/zlog.conf"
/**
 * Initializes the logging facilities
 */
void LOG_INIT(char* conf_path);

/**
 * Tears down the logging facilities
 */
void LOG_EXIT();

/**
 * Logs a debug message
 * @param format Format message
 */
void DEBUG_MSG(const char *format, ...);

/**
 * Logs an error message
 * @param format Format message
 */
void ERROR_MSG(const char *format, ...);

/**
 * Prints a message on the screen
 * @param format Format message
 */
void SCREEN_MSG(const char *format, ...);
#endif /*__LOGDEF_H__*/
