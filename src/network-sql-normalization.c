/*
 * network-sql-normalization.c
 *
 *  Created on: 2013-7-25
 *      Author: jinxuanhou
 */

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <openssl/md5.h>
#include "network-sql-normalization.h"


void merge_multi_value_for_in(char *query_sql);

#define sql_space(a)	(a == 0x20 || a == 0xA0 || (a > 0x08 && a < 0x0E))
static char TOKEN_BEGIN[] = " in (";
static char TOKEN_END[] = "N)";
/**
 * 祛除sql中的注释：包括三种#、--及类c语言的注释
 * @param query_sql
 */

#if 0
/** 祛除#这种注释，注意当#被引号引用时不能当做注释 */
static void remove_dash_comments(char *query_sql) {
	return;

}

/** 祛除--这种注释的内容，注意当--被引号引用时不能当做注释 */
static void remove_comments(char *query_sql) {
	return;
}

/**  */
static char * look_for_char(char *sql_ptr, char _char) {
	return NULL;
}

static void remove_quoted_text(char *query_sql) {
	return;
}

static void remove_spaces(char *query_sql) {
	/** 祛除sql中多余的空格 */

}
#endif

/** <实现序列化，针对限制单条sql的情况 */
/**
 * 将sql语句按照单条语句的规则进行标准化
 * @param tokens sql语句的token列表
 * @return 标准化之后的sql语句
 * @note 返回结果需要用户自己释放内存
 */
char * sql_normalize_for_single(
		const GPtrArray *tokens) {
	/**
	 * @note 此类sql的标准化只需要做一下工作：
	 * 1. 将关键字变为小写
	 * 2. 将注释、多余的空格去掉
	 * 3. 去掉换行符
	 *  不需要绑定变量替换
	 */

	if (NULL == tokens) {
		return NULL;
	}

	char * normalized_sql = NULL;
	GString *sql_buffer = g_string_new(NULL);
	sql_token *token = NULL;

	sql_token_id last_id;
	sql_token_id pre_last_id;

	if (0 < tokens->len) {
		unsigned int index = 0;
		unsigned int char_index = 0;
		for (index = 0; index < tokens->len; index++) {
			token = (sql_token *)(tokens->pdata[index]);
			// 接下来将toens组合成
			/**
			 * 输入的SQL必须进行规范化 标准如下:
			 * 1. 将开头的空格去掉;
			 * 2. 将多个空格合并成一个空格;
			 * 3. 去除回车换行符;
			 * 4. 将`db`.`table`的”` “ 符号去掉;
			 * 5. 关键字统一转换成小写
			 */
			if (token != NULL) {
				switch (token->token_id) {
				case TK_COMMENT:
				case TK_COMMENT_MYSQL:
					/** 祛除注释包括三种形式的注释：--、#、类c语言注释 */
					break;
				case TK_INTEGER:
				case TK_FLOAT:
					/**
					 * 数值转换成'?',应该包括负数 。
					 * 因而在遇到整形时需要依据前面的两个token进行判断
					 * 若：last_token 为 '-'
					 * 并且last_last_token 为：
					 * "select"、"where"、"and"、"or"、"not"、'(' 、','其中的一个即可认为该数值为负数
					 * 需要将 '- '去掉，然后添加？
					 * 反之为表达式，不是负数。
					 */
					if (index >= 2) {
						last_id = ((sql_token *)(tokens->pdata[index - 1]))->token_id;
						if (last_id == TK_MINUS) {
							pre_last_id = ((sql_token *)(tokens->pdata[index - 2]))->token_id;
							if (pre_last_id == TK_SQL_SELECT ||
									pre_last_id == TK_SQL_WHERE ||
									pre_last_id == TK_SQL_AND ||
									pre_last_id == TK_SQL_OR ||
									pre_last_id == TK_SQL_NOT ||
									pre_last_id == TK_OBRACE ||
									pre_last_id == TK_COMMA ||
									pre_last_id == TK_EQ) {
								if (sql_buffer->str[sql_buffer->len - 1] == ' ' &&
										sql_buffer->str[sql_buffer->len - 2] == '-') {
									/** 正常情况下：sql_buffer 最后的两个字符为'-'' ',将其删除 */
									g_string_erase(sql_buffer, sql_buffer->len - 1, 1);
								}
							}
						}
					}
					g_string_append(sql_buffer, token->text->str);
					g_string_append_c(sql_buffer, ' ');
					break;
				case TK_STRING:{
					/** string 替换成'?' */
					g_string_append_c(sql_buffer, '\'');
					g_string_append(sql_buffer, token->text->str);
					g_string_append_c(sql_buffer, '\'');
					g_string_append_c(sql_buffer, ' ');
					break;
				}
				case TK_DOT:
					/** '.' 前后都不需要有空格 */
					if (sql_buffer->str[sql_buffer->len - 1] == ' ') {
						g_string_erase(sql_buffer, sql_buffer->len - 1, 1);
					}
					g_string_append(sql_buffer, token->text->str);
					break;
				case TK_OBRACE:
					/** '(' 后面不需要有空格 */
					g_string_append(sql_buffer, token->text->str);
					break;
				case TK_CBRACE:
					/** ')' 之前不需要有空格 */
					if (sql_buffer->str[sql_buffer->len - 1] == ' ') {
						g_string_erase(sql_buffer, sql_buffer->len - 1, 1);
					}
					g_string_append(sql_buffer, token->text->str);
					g_string_append_c(sql_buffer, ' ');
					break;
				case TK_COMMA:
					/** ','前不需要空格 */
					if (sql_buffer->str[sql_buffer->len - 1] == ' ') {
						g_string_erase(sql_buffer, sql_buffer->len - 1, 1);
					}
					g_string_append(sql_buffer, token->text->str);
					g_string_append_c(sql_buffer, ' ');
					break;
				default:
					for (char_index = 0; char_index < token->text->len; char_index ++) {
						g_string_append_c(sql_buffer, g_ascii_tolower (token->text->str[char_index]));
					}
					g_string_append_c(sql_buffer, ' ');
				}
			}
		}
		/** 若最后一个字符是空格，则将其删除 */
		if (sql_buffer->str[sql_buffer->len - 1] == ' ') {
			g_string_erase(sql_buffer, sql_buffer->len -1, 1);
		}

		/**
		 * @note 上面在标准sql的拼接过程当中已经将接下来将sql语句中的 多余的空格去掉
		 * 包括:'('之后的、')'之前的,最后一个空格,'.'之前的和之后的,','之前的，以及负号之后的空格
		 */
	}
	if (sql_buffer->len > 0) {
		/** 接下来将in 之后的括号中的多个?合并 */
		normalized_sql = g_strndup(sql_buffer->str, sql_buffer->len);
	}

	/** 释放申请的资源 */

	if (sql_buffer != NULL) {
		g_string_free(sql_buffer, TRUE);
		sql_buffer = NULL;
	}

	return normalized_sql;
}

/**< 实现序列化，针对限制某类sql的情况 */
/**
 * 将sql语句按模版类进行标准化
 * @param tokens sql语句的token列表
 * @return 标准化之后的sql语句
 * @note 返回的标准化sql语句需要用户自己释放内存：g_free
 */
char * sql_normalize_for_template(
		const GPtrArray *tokens) {

	if (NULL == tokens) {
		return NULL;
	}

	char * normalized_sql = NULL;
	GString *sql_buffer = g_string_new(NULL);
	sql_token *token = NULL;

	sql_token_id last_id;
	sql_token_id pre_last_id;
	if (0 < tokens->len) {
		unsigned int index = 0;
		for (index = 0; index < tokens->len; index++) {
			token = (sql_token *)(tokens->pdata[index]);
			// 接下来将toens组合成
			/**
			 * 输入的SQL必须进行规范化 标准如下:
			 * 1. 替换成绑定变量;
			 * 2. 将in (1,2,3,4,5) 转换成in (N);
			 * 3. 将开头的空格去掉;
			 * 4. 将多个空格合并成一个空格;
			 * 5. 去除回车换行符;
			 * 6. 统一为小写;
			 * 7. 将`db`.`table`的”` “ 符号去掉;
			 * 8. 计算出SQL_ID,可以用MD5进行计算;
			 *
			 */
			if (token != NULL) {
				switch (token->token_id) {
				case TK_COMMENT:
				case TK_COMMENT_MYSQL:
					/** 祛除注释包括三种形式的注释：--、#、类c语言注释 */
					break;
				case TK_INTEGER:
				case TK_FLOAT:
					/**
					 * 数值转换成'?',应该包括负数 。
					 * 因而在遇到整形时需要依据前面的两个token进行判断
					 * 若：last_token 为 '-'
					 * 并且last_last_token 为：
					 * "select"、"where"、"and"、"or"、"not"、'(' 、','其中的一个即可认为该数值为负数
					 * 需要将 '- '去掉，然后添加？
					 * 反之为表达式，不是负数。
					 */
					if (index >= 2) {
						last_id = ((sql_token *)(tokens->pdata[index - 1]))->token_id;
						if (last_id == TK_MINUS) {
							pre_last_id = ((sql_token *)(tokens->pdata[index - 2]))->token_id;
							if (pre_last_id == TK_SQL_SELECT ||
									pre_last_id == TK_SQL_WHERE ||
									pre_last_id == TK_SQL_AND ||
									pre_last_id == TK_SQL_OR ||
									pre_last_id == TK_SQL_NOT ||
									pre_last_id == TK_OBRACE ||
									pre_last_id == TK_COMMA ||
									pre_last_id == TK_EQ) {
								if (sql_buffer->str[sql_buffer->len - 1] == ' ' &&
										sql_buffer->str[sql_buffer->len - 2] == '-') {
									/** 正常情况下：sql_buffer 最后的两个字符为'-'' ',将其删除 */
									g_string_erase(sql_buffer, sql_buffer->len - 2, 2);
								}
							}
						}
					}
					g_string_append(sql_buffer, "?");
					g_string_append_c(sql_buffer, ' ');
					break;
				case TK_STRING:{
					/** string 替换成'?' */
					g_string_append(sql_buffer, "?");
					g_string_append_c(sql_buffer, ' ');
					break;
				}
				case TK_DOT:
					/** '.' 前后都不需要有空格 */
					if (sql_buffer->str[sql_buffer->len - 1] == ' ') {
						g_string_erase(sql_buffer, sql_buffer->len - 1, 1);
					}
					g_string_append(sql_buffer, token->text->str);
					break;
				case TK_OBRACE:
					/** '(' 后面不需要有空格 */
					g_string_append(sql_buffer, token->text->str);
					break;
				case TK_CBRACE:
					/** ')' 之前不需要有空格 */
					if (sql_buffer->str[sql_buffer->len - 1] == ' ') {
						g_string_erase(sql_buffer, sql_buffer->len - 1, 1);
					}
					g_string_append(sql_buffer, token->text->str);
					g_string_append_c(sql_buffer, ' ');
					break;
				case TK_COMMA:
					/** ','前不需要空格 */
					if (sql_buffer->str[sql_buffer->len - 1] == ' ') {
						g_string_erase(sql_buffer, sql_buffer->len - 1, 1);
					}
					g_string_append(sql_buffer, token->text->str);
					g_string_append_c(sql_buffer, ' ');
					break;
				default:
					g_string_append(sql_buffer, token->text->str);
					g_string_append_c(sql_buffer, ' ');
				}
			}
		}
		/** 若最后一个字符是空格，则将其删除 */
		if (sql_buffer->str[sql_buffer->len - 1] == ' ') {
			g_string_erase(sql_buffer, sql_buffer->len -1, 1);
		}

		/**
		 * @note 上面在标准sql的拼接过程当中已经将接下来将sql语句中的 多余的空格去掉
		 * 包括:'('之后的、')'之前的,最后一个空格,'.'之前的和之后的,','之前的，以及负号之后的空格
		 * 同时将负数转换成了 '?'
		 */
	}
	if (sql_buffer->len > 0) {
		/** 接下来将in 之后的括号中的多个?合并 */
		sql_buffer = g_string_ascii_down (sql_buffer); /**< 这里不会重新分配的空间 */
		normalized_sql = g_strndup(sql_buffer->str, sql_buffer->len);

	}

	/** 释放申请的资源 */

	if (sql_buffer != NULL) {
		g_string_free(sql_buffer, TRUE);
		sql_buffer = NULL;
	}

	merge_multi_value_for_in(normalized_sql);
	return normalized_sql;
}

/**
 * 将标准化语句中的in (?, ?, ?)转换成in (N)
 * @note 会对传入的阐述query_sql 进行修改
 * @param query_sql 需要进行修改的sql语句
 */
void merge_multi_value_for_in(char *query_sql) {
	char *cur = query_sql;
	char *post = query_sql;
	char * index = NULL;
	int pos = 0;
	int c_bracket = 0;

	/** 特殊情况时in 里面嵌套in */
	while (post && '\0' != *post) {
		index = strstr(post, " in (");
		if (index == NULL) {
			while ('\0' != *post) {
				*cur = *post++;
				cur++;
			}
		} else {
			/** 找到' in ('关键字, 先将post-->index 之间的字符赋予保留下来*/
			while (post < index) {
				*cur = *post++;
				cur++;
			}

			/** 将' in ('拷贝到cur中 */
			pos = 0;
			while ('\0' != TOKEN_BEGIN[pos]) {
				*cur = TOKEN_BEGIN[pos++];
				cur++;
				post++;
			}

			if ('\0' != *post) {
				if (*post == '?') {
					/** 如果括号内的第一个字母是'?',
					 * 我们认为遇到了in (?, ?, ?) 这种格式，
					 * post 遍历到下一个与 in 开始对应的')',然后向cur 赋予 "N)"
					 * 以为着post遍历过的字符'?, ? ...)'将被替换
					 **/
					c_bracket = 0;
					while (c_bracket <= 0 && '\0' != *post) {
						if ('(' == *post) {
							c_bracket--;
						} else if (')' == *post) {
							c_bracket++;
						}
						post++;
					}
					pos = 0;
					while ('\0' != TOKEN_END[pos]) {
						*cur = TOKEN_END[pos++];
						cur++;
					}
				}
			}
		}
	}
	/** 语句结尾补全'\0'字符串 */
	if (cur) {
		*cur = '\0';
	}
}

/**
 * 实现对传入的sql语句的标准化，返回标准化之后的sql语句
 * 在我们需要用到词法分析对sql语句进行序列化时，需要首先将# 和 -- 对应的注释祛除
 * @param sql_original
 * @return 标准化之后的sql语句
 * @note 返回的sql语句内存需要调用者释放
 */
char * sql_normalize_with_token(
		const char *sql_original,
		normalize_type type) {

	g_assert(NORMALIZE_FOR_SINGLE == type ||
			NORMALIZE_FOR_TEMPLATE == type);

	if (sql_original == NULL)
		return NULL;

	char *normalized_sql = NULL;
	GPtrArray *tokens = g_ptr_array_new();
	sql_tokenizer(tokens, sql_original, strlen(sql_original));

	switch (type) {
	case NORMALIZE_FOR_SINGLE:
		normalized_sql = sql_normalize_for_single(tokens);
		break;
	case NORMALIZE_FOR_TEMPLATE:
		normalized_sql = sql_normalize_for_template(tokens);
		break;
	default:
		g_assert_not_reached();
	}

	if (tokens != NULL) {
		sql_tokens_free(tokens);
		tokens = NULL;
	}

	return normalized_sql;
}

/**
 * 实现对传入的sql语句的标准化，若token非空则利用原来的token列表
 * 返回标准化之后的sql语句
 * @note 返回的语句内存需要调用者自己释放
 */
char * sql_normalize_with_token_dispatch(const GPtrArray *tokens,
		const char *sql_original, normalize_type type) {
	g_assert(NORMALIZE_FOR_SINGLE == type || NORMALIZE_FOR_TEMPLATE == type);

	if (sql_original == NULL ) {
		return NULL ;
	}

	char *normalized_sql = NULL;

	if (NULL != tokens) {
		if (NORMALIZE_FOR_SINGLE == type) {
			normalized_sql = sql_normalize_for_single(tokens);
		} else {
			normalized_sql = sql_normalize_for_template(tokens);
		}
	} else {
		normalized_sql = sql_normalize_with_token(sql_original, type);
	}

	return normalized_sql;
}

/**
 * 不采用词法分析的方式而是直接对
 * sql语句进行扫描直接进行标准化学习greensql
 * @param sql_original
 * @return
 */
char *sql_normalize_without_token(
		const char G_GNUC_UNUSED *sql_original) {
	return NULL;
}

/** 对标准化时候的sql语句求md5值  使用的md5函数是：*/
/**
 * 将传进的sql语句序列化
 * @param sql_normalized 标准化的sql语句
 * @return MD5字符串
 * @note 需要用户自己释放变量内存
 */
char * sql_normalize_MD5(
		const char *sql_normalized) {
	if (NULL == sql_normalized) {
		return NULL;
	}
	char * ret = g_new0(char, MD5_DIGEST_LENGTH * 2 + 1);
	MD5_CTX ctx;
	unsigned char md[MD5_DIGEST_LENGTH];

	MD5_Init(&ctx);
	MD5_Update(&ctx, (void *)sql_normalized, strlen(sql_normalized));
	MD5_Final(md, &ctx);
	int index = 0;
	for (index = 0; index < MD5_DIGEST_LENGTH; index++) {
		sprintf(ret + 2 * index, "%02x", md[index]);
	}
	ret[MD5_DIGEST_LENGTH * 2] = '\0';
	return ret;
}
