/*
 * chassis-regex.c
 *
 *  Created on: 2013-5-23
 *      Author: jinxuanhou
 */

#include <stdio.h>
#include <glib.h>

#include "chassis-exports.h"
#include "chassis-regex.h"
#include "glib-ext.h"

#define CHARSET_ARRAY_LEN 254

const char * charset_dic[] = { "", "big5", "latin2", "dec8", "cp850", "latin1",
		"hp8", "koi8r", "latin1", "latin2", "swe7", "ascii", "ujis", "sjis",
		"cp1251", "latin1", "hebrew", "", "tis620", "euckr", "latin7", "latin2",
		"koi8u", "cp1251", "gb2312", "greek", "cp1250", "latin2", "gbk",
		"cp1257", "latin5", "latin1", "armscii8", "utf8", "cp1250", "ucs2",
		"cp866", "keybcs2", "macce", "macroman", "cp852", "latin7", "latin7",
		"macce", "cp1250", "utf8mb4", "utf8mb4", "latin1", "latin1", "latin1",
		"cp1251", "cp1251", "cp1251", "macroman", "utf16", "utf16", "",
		"cp1256", "cp1257", "cp1257", "utf32", "utf32", "", "binary",
		"armscii8", "ascii", "cp1250", "cp1256", "cp866", "dec8", "greek",
		"hebrew", "hp8", "keybcs2", "koi8r", "koi8u", "", "latin2", "latin5",
		"latin7", "cp850", "cp852", "swe7", "utf8", "big5", "euckr", "gb2312",
		"gbk", "sjis", "tis620", "ucs2", "ujis", "geostd8", "geostd8", "latin1",
		"cp932", "cp932", "eucjpms", "eucjpms", "cp1250", "", "utf16", "utf16",
		"utf16", "utf16", "utf16", "utf16", "utf16", "utf16", "utf16", "utf16",
		"utf16", "utf16", "utf16", "utf16", "utf16", "utf16", "utf16", "utf16",
		"utf16", "utf16", "", "", "", "", "", "", "", "ucs2", "ucs2", "ucs2",
		"ucs2", "ucs2", "ucs2", "ucs2", "ucs2", "ucs2", "ucs2", "ucs2", "ucs2",
		"ucs2", "ucs2", "ucs2", "ucs2", "ucs2", "ucs2", "ucs2", "ucs2", "", "",
		"", "", "", "", "", "", "", "", "", "ucs2", "utf32", "utf32", "utf32",
		"utf32", "utf32", "utf32", "utf32", "utf32", "utf32", "utf32", "utf32",
		"utf32", "utf32", "utf32", "utf32", "utf32", "utf32", "utf32", "utf32",
		"utf32", "", "", "", "", "", "", "", "", "", "", "", "", "utf8", "utf8",
		"utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8",
		"utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8",
		"", "", "", "", "", "", "", "", "", "", "", "utf8", "utf8mb4",
		"utf8mb4", "utf8mb4", "utf8mb4", "utf8mb4", "utf8mb4", "utf8mb4",
		"utf8mb4", "utf8mb4", "utf8mb4", "utf8mb4", "utf8mb4", "utf8mb4",
		"utf8mb4", "utf8mb4", "utf8mb4", "utf8mb4", "utf8mb4", "utf8mb4",
		"utf8mb4", "", "", "", "", "", "", "", "", "", "utf8" };

const char *collation_dic[] = { "", "big5_chinese_ci", "latin2_czech_cs",
		"dec8_swedish_ci", "cp850_general_ci", "latin1_german1_ci",
		"hp8_english_ci", "koi8r_general_ci", "latin1_swedish_ci",
		"latin2_general_ci", "swe7_swedish_ci", "ascii_general_ci",
		"ujis_japanese_ci", "sjis_japanese_ci", "cp1251_bulgarian_ci",
		"latin1_danish_ci", "hebrew_general_ci", "", "tis620_thai_ci",
		"euckr_korean_ci", "latin7_estonian_cs", "latin2_hungarian_ci",
		"koi8u_general_ci", "cp1251_ukrainian_ci", "gb2312_chinese_ci",
		"greek_general_ci", "cp1250_general_ci", "latin2_croatian_ci",
		"gbk_chinese_ci", "cp1257_lithuanian_ci", "latin5_turkish_ci",
		"latin1_german2_ci", "armscii8_general_ci", "utf8_general_ci",
		"cp1250_czech_cs", "ucs2_general_ci", "cp866_general_ci",
		"keybcs2_general_ci", "macce_general_ci", "macroman_general_ci",
		"cp852_general_ci", "latin7_general_ci", "latin7_general_cs",
		"macce_bin", "cp1250_croatian_ci", "utf8mb4_general_ci", "utf8mb4_bin",
		"latin1_bin", "latin1_general_ci", "latin1_general_cs", "cp1251_bin",
		"cp1251_general_ci", "cp1251_general_cs", "macroman_bin",
		"utf16_general_ci", "utf16_bin", "", "cp1256_general_ci", "cp1257_bin",
		"cp1257_general_ci", "utf32_general_ci", "utf32_bin", "", "binary",
		"armscii8_bin", "ascii_bin", "cp1250_bin", "cp1256_bin", "cp866_bin",
		"dec8_bin", "greek_bin", "hebrew_bin", "hp8_bin", "keybcs2_bin",
		"koi8r_bin", "koi8u_bin", "", "latin2_bin", "latin5_bin", "latin7_bin",
		"cp850_bin", "cp852_bin", "swe7_bin", "utf8_bin", "big5_bin",
		"euckr_bin", "gb2312_bin", "gbk_bin", "sjis_bin", "tis620_bin",
		"ucs2_bin", "ujis_bin", "geostd8_general_ci", "geostd8_bin",
		"latin1_spanish_ci", "cp932_japanese_ci", "cp932_bin",
		"eucjpms_japanese_ci", "eucjpms_bin", "cp1250_polish_ci", "",
		"utf16_unicode_ci", "utf16_icelandic_ci", "utf16_latvian_ci",
		"utf16_romanian_ci", "utf16_slovenian_ci", "utf16_polish_ci",
		"utf16_estonian_ci", "utf16_spanish_ci", "utf16_swedish_ci",
		"utf16_turkish_ci", "utf16_czech_ci", "utf16_danish_ci",
		"utf16_lithuanian_ci", "utf16_slovak_ci", "utf16_spanish2_ci",
		"utf16_roman_ci", "utf16_persian_ci", "utf16_esperanto_ci",
		"utf16_hungarian_ci", "utf16_sinhala_ci", "", "", "", "", "", "", "",
		"ucs2_unicode_ci", "ucs2_icelandic_ci", "ucs2_latvian_ci",
		"ucs2_romanian_ci", "ucs2_slovenian_ci", "ucs2_polish_ci",
		"ucs2_estonian_ci", "ucs2_spanish_ci", "ucs2_swedish_ci",
		"ucs2_turkish_ci", "ucs2_czech_ci", "ucs2_danish_ci",
		"ucs2_lithuanian_ci", "ucs2_slovak_ci", "ucs2_spanish2_ci",
		"ucs2_roman_ci", "ucs2_persian_ci", "ucs2_esperanto_ci",
		"ucs2_hungarian_ci", "ucs2_sinhala_ci", "", "", "", "", "", "", "", "",
		"", "", "", "ucs2_general50_ci", "utf32_unicode_ci",
		"utf32_icelandic_ci", "utf32_latvian_ci", "utf32_romanian_ci",
		"utf32_slovenian_ci", "utf32_polish_ci", "utf32_estonian_ci",
		"utf32_spanish_ci", "utf32_swedish_ci", "utf32_turkish_ci",
		"utf32_czech_ci", "utf32_danish_ci", "utf32_lithuanian_ci",
		"utf32_slovak_ci", "utf32_spanish2_ci", "utf32_roman_ci",
		"utf32_persian_ci", "utf32_esperanto_ci", "utf32_hungarian_ci",
		"utf32_sinhala_ci", "", "", "", "", "", "", "", "", "", "", "", "",
		"utf8_unicode_ci", "utf8_icelandic_ci", "utf8_latvian_ci",
		"utf8_romanian_ci", "utf8_slovenian_ci", "utf8_polish_ci",
		"utf8_estonian_ci", "utf8_spanish_ci", "utf8_swedish_ci",
		"utf8_turkish_ci", "utf8_czech_ci", "utf8_danish_ci",
		"utf8_lithuanian_ci", "utf8_slovak_ci", "utf8_spanish2_ci",
		"utf8_roman_ci", "utf8_persian_ci", "utf8_esperanto_ci",
		"utf8_hungarian_ci", "utf8_sinhala_ci", "", "", "", "", "", "", "", "",
		"", "", "", "utf8_general_mysql500_ci", "utf8mb4_unicode_ci",
		"utf8mb4_icelandic_ci", "utf8mb4_latvian_ci", "utf8mb4_romanian_ci",
		"utf8mb4_slovenian_ci", "utf8mb4_polish_ci", "utf8mb4_estonian_ci",
		"utf8mb4_spanish_ci", "utf8mb4_swedish_ci", "utf8mb4_turkish_ci",
		"utf8mb4_czech_ci", "utf8mb4_danish_ci", "utf8mb4_lithuanian_ci",
		"utf8mb4_slovak_ci", "utf8mb4_spanish2_ci", "utf8mb4_roman_ci",
		"utf8mb4_persian_ci", "utf8mb4_esperanto_ci", "utf8mb4_hungarian_ci",
		"utf8mb4_sinhala_ci", "", "", "", "", "", "", "", "", "",
		"utf8_general50_ci" };

#define DISTINCT_CHARSET_NUM 39

const char *distinct_sets[] = { "armscii8", "ascii", "big5", "binary", "cp1250",
		"cp1251", "cp1256", "cp1257", "cp850", "cp852", "cp866", "cp932",
		"dec8", "eucjpms", "euckr", "gb2312", "gbk", "geostd8", "greek",
		"hebrew", "hp8", "keybcs2", "koi8r", "koi8u", "latin1", "latin2",
		"latin5", "latin7", "macce", "macroman", "sjis", "swe7", "tis620",
		"ucs2", "ujis", "utf16", "utf32", "utf8", "utf8mb4",NULL };

const char *distinct_collations[] = { "armscii8_general_ci", "ascii_general_ci",
		"big5_chinese_ci", "binary", "cp1250_general_ci", "cp1251_general_ci",
		"cp1256_general_ci", "cp1257_general_ci", "cp850_general_ci",
		"cp852_general_ci", "cp866_general_ci", "cp932_japanese_ci",
		"dec8_swedish_ci", "eucjpms_japanese_ci", "euckr_korean_ci",
		"gb2312_chinese_ci", "gbk_chinese_ci", "geostd8_general_ci",
		"greek_general_ci", "hebrew_general_ci", "hp8_english_ci",
		"keybcs2_general_ci", "koi8r_general_ci", "koi8u_general_ci",
		"latin1_swedish_ci", "latin2_general_ci", "latin5_turkish_ci",
		"latin7_general_ci", "macce_general_ci", "macroman_general_ci",
		"sjis_japanese_ci", "swe7_swedish_ci", "tis620_thai_ci",
		"ucs2_general_ci", "ujis_japanese_ci", "utf16_general_ci",
		"utf32_general_ci", "utf8_general_ci", "utf8mb4_general_ci",
		NULL };

GHashTable *distinct_set_name = NULL;
GHashTable *collation_name_index_mapping = NULL;

gchar *charset_client_str = "[\\s\\S]*set[\\s\\S]+character_set_client";
gchar *charset_connect_str = "[\\s\\S]*set[\\s\\S]+character_set_connection";
gchar *charset_results_str = "[\\s\\S]*set[\\s\\S]+character_set_results";
gchar *charset_database_str = "[\\s\\S]*set[\\s\\S]+character_set_database";
gchar *charset_server_str = "[\\s\\S]*set[\\s\\S]+character_set_server";
gchar *charset_names_str = "[\\s\\S]*set[\\s\\S]+names";
gchar *collation_connect_str="[\\s\\S]*set[\\s\\S]+collation_connection";


charset_regex *charset_regex_new(void) {
	if (distinct_set_name != NULL) {
		g_debug("distinct_set_name not null?");
		g_hash_table_destroy (distinct_set_name);
		distinct_set_name = NULL;
	}
	distinct_set_name = g_hash_table_new_full(
			g_hash_table_charset_string_hash,
			g_hash_table_charset_string_equal,
			g_hash_table_string_free,
			g_hash_table_int_free);

	collation_name_index_mapping = g_hash_table_new_full(
			g_hash_table_charset_string_hash,
			g_hash_table_charset_string_equal,
			g_hash_table_string_free,
			g_hash_table_int_free);

	charset_regex *regs = g_new0(charset_regex, 1);
	GString *key = NULL;
	gint *value = NULL;
	int index = 0;
	for (index = 0; index < 39; index++) {
		key = g_string_new(distinct_sets[index]);
		value = g_new0(gint, 1);
		*value = index;
		g_hash_table_insert(distinct_set_name, key, value);
	}

	for (index = 0; index < CHARSET_ARRAY_LEN; index++) {
		if (collation_dic[index] != NULL) {
			key = g_string_new(collation_dic[index]);
			value = g_new0(gint, 1);
			*value = index;
			g_hash_table_insert(collation_name_index_mapping, key, value);
			key = NULL;
		}
	}

	regs->names_set = g_regex_new(charset_names_str, G_REGEX_CASELESS, 0, NULL);
	regs->client_char_set = g_regex_new(charset_client_str, G_REGEX_CASELESS, 0, NULL);
	regs->connect_char_set = g_regex_new(charset_connect_str, G_REGEX_CASELESS, 0, NULL);
	regs->results_char_set = g_regex_new(charset_results_str, G_REGEX_CASELESS, 0, NULL);
	regs->database_char_set = g_regex_new(charset_database_str, G_REGEX_CASELESS, 0, NULL);
	regs->server_char_set = g_regex_new(charset_server_str, G_REGEX_CASELESS, 0, NULL);
	regs->connect_coll = g_regex_new(collation_connect_str, G_REGEX_CASELESS, 0, NULL);

	return regs;
}

void charset_regex_free(charset_regex *reg) {
	if(!reg)
		return;

	if(reg->names_set)
		g_regex_unref (reg->names_set);
	if(reg->client_char_set)
		g_regex_unref(reg->client_char_set);
	if(reg->connect_char_set)
		g_regex_unref(reg->connect_char_set);
	if(reg->results_char_set)
		g_regex_unref(reg->results_char_set);
	if(reg->database_char_set)
		g_regex_unref(reg->database_char_set);
	if(reg->server_char_set)
		g_regex_unref(reg->server_char_set);

	if(reg->connect_coll)
		g_regex_unref(reg->connect_coll);

	if (distinct_set_name != NULL) {
		g_hash_table_destroy (distinct_set_name);
		distinct_set_name = NULL;
	}

	g_free(reg);
}

gboolean is_set_names(charset_regex *reg, const gchar *sql) {
	g_assert(reg);
	g_assert(sql);
	g_assert(reg->names_set);

	gboolean ret = FALSE;
	GMatchInfo *match_info;
	if(g_regex_match(reg->names_set, sql, 0, &match_info)) {
		ret = TRUE;
	}
	g_match_info_free (match_info);
	return ret;
}
gboolean is_set_client_charset(charset_regex *reg, const gchar *sql) {
	g_assert(reg);
	g_assert(sql);
	g_assert(reg->client_char_set);

	gboolean ret = FALSE;
	GMatchInfo *match_info;
	if(g_regex_match(reg->client_char_set, sql, 0, &match_info)) {
		ret = TRUE;
	}
	g_match_info_free (match_info);
	return ret;
}
gboolean is_set_connect_charset(charset_regex *reg, const gchar *sql) {
	g_assert(reg);
	g_assert(sql);
	g_assert(reg->connect_char_set);

	gboolean ret = FALSE;
	GMatchInfo *match_info;
	if(g_regex_match(reg->connect_char_set, sql, 0, &match_info)) {
		ret = TRUE;
	}
	g_match_info_free (match_info);
	return ret;
}
gboolean is_set_results_charset(charset_regex *reg, const gchar *sql) {
	g_assert(reg);
	g_assert(sql);
	g_assert(reg->results_char_set);

	gboolean ret = FALSE;
	GMatchInfo *match_info;
	if(g_regex_match(reg->results_char_set, sql, 0, &match_info)) {
		ret = TRUE;
	}
	g_match_info_free (match_info);
	return ret;
}
gboolean is_set_database_charset(charset_regex *reg, const gchar *sql) {
	g_assert(reg);
	g_assert(sql);
	g_assert(reg->database_char_set);

	gboolean ret = FALSE;
	GMatchInfo *match_info;
	if(g_regex_match(reg->database_char_set, sql, 0, &match_info)) {
		ret = TRUE;
	}
	g_match_info_free (match_info);
	return ret;
}
gboolean is_set_server_charset(charset_regex *reg, const gchar *sql) {
	g_assert(reg);
	g_assert(sql);
	g_assert(reg->server_char_set);

	gboolean ret = FALSE;
	GMatchInfo *match_info;
	if(g_regex_match(reg->server_char_set, sql, 0, &match_info)) {
		ret = TRUE;
	}
	g_match_info_free (match_info);
	return ret;
}

gboolean is_correct_charsetname(const gchar *charset) {
	if (!charset || (charset == '\0'))
		return FALSE;
	GString *_key = g_string_new(charset);
	//printf("%s===============================================%d\n", _key->str, _key->len);
	gint *value = NULL;
	if (!distinct_set_name) {
		g_debug("no distinct_set_name?");
		distinct_set_name = g_hash_table_new_full(g_hash_table_charset_string_hash, g_hash_table_charset_string_equal, g_hash_table_string_free, g_hash_table_int_free);
		GString *key = NULL;
        	value = NULL;
 	        int index = 0;
        	for (index = 0; index < 39; index++) {
                	key = g_string_new(distinct_sets[index]);
                	value = g_new0(gint, 1);
                	*value = index;
                	g_hash_table_insert(distinct_set_name, key, value);
        	}
	}
	
	//printf("%s===============================================%d\n", _key->str, _key->len);
	value = g_hash_table_lookup(distinct_set_name, _key);
	//printf("%s===============================================%d\n", _key->str, _key->len);
	if (_key) {
		g_string_free(_key, TRUE);
	}
	if (!value) {
		return FALSE;
	} else {
		return TRUE;
	}
}

gboolean is_set_connect_collation(charset_regex *reg, const gchar *sql) {
	g_assert(reg);
	g_assert(sql);
	g_assert(reg->connect_coll);

	gboolean ret = FALSE;
	GMatchInfo *match_info;
	if(g_regex_match(reg->connect_coll, sql, 0, &match_info)) {
		ret = TRUE;
	}
	g_match_info_free (match_info);
	return ret;
}

/**< 获取对应字符集的默认的校验下标 */
gint get_default_collation_index(const gchar *charset) {
	if (NULL == charset) {
		return -1;
	}

	/**
	 * 先实现一个简单的二分查找吧，因为是有序的!!
	 * 可以考虑后缀树?hash?
	 * 最简单的是维护一个字典就行了
	 */
	gint pre = 0;
	gint post = DISTINCT_CHARSET_NUM - 1;
	gint mid;
	while (pre <= post) {
		mid = (pre + post)/2;
		if (0 == g_ascii_strcasecmp(charset, distinct_sets[mid])) {
			return mid;
		} else if (0 < g_ascii_strcasecmp(charset, distinct_sets[mid])) {
			pre = mid + 1;
		} else {
			post = mid - 1;
		}
	}

	return -1;
}

/**< 验证一个校验的名字是否正确,不计大小写 */
gboolean is_correct_collationname(const gchar *collation, guint8 *index) {
	if (!collation || (collation == '\0')) {
		return FALSE;
	}

	GString *_key = g_string_new(collation);
	gint *value = NULL;
	if (!distinct_set_name) {
		g_debug("no distinct_set_name?");
		collation_name_index_mapping = g_hash_table_new_full(
				g_hash_table_charset_string_hash,
				g_hash_table_charset_string_equal,
				g_hash_table_string_free,
				g_hash_table_int_free);

		GString *key = NULL;
		value = NULL;
		int index = 0;
		for (index = 0; index < CHARSET_ARRAY_LEN; index++) {
			key = g_string_new(distinct_sets[index]);
			value = g_new0(gint, 1);
			*value = index;
			g_hash_table_insert(collation_name_index_mapping, key, value);
		}
	}

	value = g_hash_table_lookup(collation_name_index_mapping, _key);

	if (_key) {
		g_string_free(_key, TRUE);
	}
	if (!value) {
		return FALSE;
	} else {
		if (index) {
			*index = (guint8)(*value);
		}
		return TRUE;
	}
}

