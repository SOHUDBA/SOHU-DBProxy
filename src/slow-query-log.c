/* $%BEGINLICENSE%$
 Copyright (c) 2014, Sohu and/or its affiliates. All rights reserved.

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
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#ifndef WIN32
#include <unistd.h> /* close */
/* define eventlog types when not on windows, saves code below */
#define EVENTLOG_ERROR_TYPE	0x0001
#define EVENTLOG_WARNING_TYPE	0x0002
#define EVENTLOG_INFORMATION_TYPE	0x0004
#else
#include <windows.h>
#include <io.h>
#define STDERR_FILENO 2
#endif
#include <glib.h>
#include <sys/time.h>

#include "glib-ext.h"
#include "network-exports.h"
#include "slow-query-log.h"

#define S(x) x->str, x->len

/**
 * slow_query_log_filter_t
 */

static void slow_query_log_filter_t_free(slow_query_log_filter_t *filter) {
	if (filter != NULL) {
		filter->time_threshold_s = 0;
		filter->time_threshold_us = 0;
		g_free(filter);
	}
	return;
}

static slow_query_log_filter_t *slow_query_log_filter_t_new(void) {
	slow_query_log_filter_t *filter = NULL;
	filter = g_new0(slow_query_log_filter_t, 1);
	return filter;
}


/**
 * slow_query_log_entry_t
 */

static void slow_query_log_entry_t_init(slow_query_log_entry_t *entry) {
	if (entry != NULL) {
		entry->service_type = NULL;
		entry->service_address = NULL;
		entry->frontend_address = NULL;
		entry->backend_address = NULL;
		entry->start_time = 0;
		entry->finish_time = 0;
		entry->execute_time = 0;
		//entry->start_time_str = NULL;
		//entry->finish_time_str = NULL;
		entry->thread_id = 0;
		entry->database_account = NULL;
		entry->database_schema = NULL;
		entry->command_type = 0;
		entry->command_text = NULL;
		entry->command_full_text = NULL;
		entry->result_set_rows = 0;
		entry->result_set_bytes = 0;
	}
	return;
}

static void slow_query_log_entry_t_free(slow_query_log_entry_t *entry) {
	if (entry != NULL) {
		if (entry->start_time_str != NULL) {
			g_string_free(entry->start_time_str, TRUE);
			entry->start_time_str = NULL;
		}
		if (entry->finish_time_str != NULL) {
			g_string_free(entry->finish_time_str, TRUE);
			entry->finish_time_str = NULL;
		}
		slow_query_log_entry_t_init(entry);
		g_free(entry);
	}
	return;
}

static slow_query_log_entry_t *slow_query_log_entry_t_new(void) {
	slow_query_log_entry_t *entry = NULL;
	entry = g_new0(slow_query_log_entry_t, 1);
	if (entry != NULL) {
		slow_query_log_entry_t_init(entry);
		entry->start_time_str = g_string_sized_new(sizeof("2014-01-01T00:00:00.000000Z"));
		entry->finish_time_str = g_string_sized_new(sizeof("2014-01-01T00:00:00.000000Z"));
		if (entry->start_time_str == NULL || entry->finish_time_str == NULL) {
			slow_query_log_entry_t_free(entry);
			entry = NULL;
		}
	}
	return entry;
}


/**
 * slow_query_log_file_t
 */

static gboolean slow_query_log_file_open(slow_query_log_file_t *log_file) {
	if (log_file->log_filename == NULL) {
		return FALSE;
	} else {
		log_file->log_file_fd = open(log_file->log_filename, O_RDWR | O_CREAT | O_APPEND, 0660);
		return (log_file->log_file_fd != -1);
	}
}

static gboolean slow_query_log_file_close(slow_query_log_file_t *log_file) {
	if (log_file->log_file_fd != -1) {
		close(log_file->log_file_fd);
		log_file->log_file_fd = -1;
	}
	return TRUE;
}

int slow_query_log_file_write(slow_query_log_file_t *log_file, GString *str) {
	if (-1 != log_file->log_file_fd) {
		write(log_file->log_file_fd, S(str));
		write(log_file->log_file_fd, "\n", 1);
	}
	return 0;
}

static void slow_query_log_file_t_free(slow_query_log_file_t *log_file) {
	if (log_file != NULL) {
		g_mutex_lock ( &(log_file->mlock) );
		slow_query_log_file_close(log_file);
		if (log_file->log_entry != NULL) {
			slow_query_log_entry_t_free(log_file->log_entry);
			log_file->log_entry = NULL;
		}
		if (log_file->log_ts_str != NULL) {
			g_string_free(log_file->log_ts_str, TRUE);
			log_file->log_ts_str = NULL;
		}
		g_mutex_unlock ( &(log_file->mlock) );
		g_mutex_clear ( &(log_file->mlock) );
		if (log_file->log_filename != NULL) {
			g_free(log_file->log_filename);
			log_file->log_filename = NULL;
		}
		g_free(log_file);
	}
	return;
}

static slow_query_log_file_t *slow_query_log_file_t_new(void) {
	slow_query_log_file_t *log_file = NULL;
	log_file = g_new0(slow_query_log_file_t, 1);
	if (log_file != NULL) {
		log_file->log_filename = NULL;
		g_mutex_init ( &(log_file->mlock) );
		g_mutex_lock ( &(log_file->mlock) );
		log_file->log_file_fd = -1;
		log_file->log_entry = slow_query_log_entry_t_new();
		log_file->log_ts_str = g_string_sized_new(sizeof("2014-01-01T00:00:00.000000Z"));
		if (log_file->log_entry == NULL || log_file->log_ts_str == NULL) {
			g_mutex_unlock ( &(log_file->mlock) );
			slow_query_log_file_t_free(log_file);
			log_file = NULL;
		} else {
			g_mutex_unlock ( &(log_file->mlock) );
		}
	}
	return log_file;
}


/**
 * slow_query_log_config_t
 */

void slow_query_log_config_t_free(slow_query_log_config_t *config) {
	if (config != NULL) {
		g_rw_lock_writer_lock( &(config->rwlock) );
		config->is_enabled = FALSE;
		if (config->log_file != NULL) {
			slow_query_log_file_t_free(config->log_file);
			config->log_file = NULL;
		}
		if (config->filter != NULL) {
			slow_query_log_filter_t_free(config->filter);
			config->filter = NULL;
		}
		g_rw_lock_writer_unlock( &(config->rwlock) );
		g_rw_lock_clear( &(config->rwlock) );
		g_free(config);
	}
	return;
}

slow_query_log_config_t *slow_query_log_config_t_new(void) {
	slow_query_log_config_t *config = NULL;
	config = g_new0(slow_query_log_config_t, 1);
	if (config != NULL) {
		g_rw_lock_init ( &(config->rwlock) );
		g_rw_lock_writer_lock ( &(config->rwlock) );
		config->is_enabled = FALSE;
		config->log_file = slow_query_log_file_t_new();
		config->filter = slow_query_log_filter_t_new();
		if (config->log_file == NULL || config->filter == NULL) {
			g_rw_lock_writer_unlock ( &(config->rwlock) );
			slow_query_log_config_t_free(config);
			config = NULL;
		} else {
			g_rw_lock_writer_unlock ( &(config->rwlock) );
		}
	}
	return config;
}


/**
 * print slow query log
 */

gboolean slow_query_log_enable(slow_query_log_config_t *config) {
	g_assert(config);
	g_rw_lock_writer_lock ( &(config->rwlock) );
	if (config->is_enabled == FALSE || config->log_file->log_file_fd == -1) {
		g_mutex_lock ( &(config->log_file->mlock) );
		if (slow_query_log_file_open(config->log_file) == TRUE) {
			g_debug("slow log enabled: %s", config->log_file->log_filename);
			config->is_enabled = TRUE;
		} else {
			g_warning("open slow log failed: %s", config->log_file->log_filename);
			config->is_enabled = FALSE;
		}
		g_mutex_unlock ( &(config->log_file->mlock) );
	}
	g_rw_lock_writer_unlock ( &(config->rwlock) );
	return (config->is_enabled == TRUE);
}

gboolean slow_query_log_disable(slow_query_log_config_t *config) {
	g_assert(config);
	g_rw_lock_writer_lock ( &(config->rwlock) );
	if (config->is_enabled == TRUE || config->log_file->log_file_fd != -1) {
		g_mutex_lock ( &(config->log_file->mlock) );
		slow_query_log_file_close(config->log_file);
		g_debug("slow log disabled: %s", config->log_file->log_filename);
		g_mutex_unlock ( &(config->log_file->mlock) );
		config->is_enabled = FALSE;
	}
	g_rw_lock_writer_unlock ( &(config->rwlock) );
	return (config->is_enabled == FALSE);
}


int slow_query_log_update_timestamp(slow_query_log_file_t *log) {
	struct tm *tm;
	GTimeVal tv;
	time_t t;
	GString *s = log->log_ts_str;

	g_get_current_time(&tv);
	t = (time_t) tv.tv_sec;
	tm = localtime(&t);

	s->len = strftime(s->str, s->allocated_len, "%Y-%m-%dT%H:%M:%S", tm);
	g_string_append_printf(s, ".%.6ld", tv.tv_usec);

	return 0;
}


/*eof*/
