/*
 * libxml-ext.c
 *
 *  Created on: 2013-8-21
 *      Author: zhenfan
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlstring.h>

#include "libxml-ext.h"

/**
 * 获取xml 文件对应的解析doc变量
 * @param xmlFile
 * @return 返回xmlDoc指针，如果文件不存在返回NULL
 */
CHASSIS_API xmlDocPtr xml_get_file_ptr(const gchar *xmlFile) {
	if (NULL == xmlFile) {
		return NULL;
	} 
	xmlDocPtr pdoc = NULL;
	// 读文件的时候设置XML_PARSE_NOBLANKS,保证读的文件没有空格回车
	pdoc = xmlReadFile(xmlFile, "utf-8", XML_PARSE_NOBLANKS);
	return pdoc;
}

/**
 * 获取xml文件的根节点
 * @param docptr
 * @return 返回xmlNodePtr指针，如果根节点不存在返回NULL
 */
CHASSIS_API xmlNodePtr xml_get_file_node_root(const xmlDocPtr docptr) {
	if (NULL == docptr) {
		return NULL;
	}

	xmlNodePtr rootptr = NULL;
	rootptr = xmlDocGetRootElement(docptr);

	return rootptr;
}

/**
 * 根据xpath获取结果集
 * @param docptr
 * @param xpath语句
 * @return 返回结果对象指针，种种原因导致的结果集不存在返回NULL
 */
CHASSIS_API xmlXPathObjectPtr xml_xpath_get_nodeset(const xmlDocPtr docptr, const xmlChar *xpath) {
	xmlXPathContextPtr context = NULL;
	xmlXPathObjectPtr  result = NULL; 
	// 创建一个XPath上下文指针
	context = xmlXPathNewContext(docptr);    
	
	if (NULL == context) {
		return NULL;
	}
	
	// 利用xpath查询得到结果集
	result = xmlXPathEvalExpression(xpath, context);
	xmlXPathFreeContext(context);
	
	// 结果对象为空
	if (NULL == result) {
		return NULL;
	}
	
	// 结果对象的nodeset为空
	if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
		xmlXPathFreeObject(result);
		return NULL;
	}
	return result;
}

/**
 * 根据xpath判断结果集是否存在，如果存在返回个数，不存在返回0
 * @param docptr
 * @param xpath语句
 * @return 存在返回个数，不存在返回0
 */
CHASSIS_API gint xml_xpath_get_nodeset_count(const xmlDocPtr docptr, const xmlChar *xpath) {
	xmlXPathContextPtr context = NULL;
	xmlXPathObjectPtr  result = NULL; 
	gint count = 0;
	// 创建一个XPath上下文指针
	context = xmlXPathNewContext(docptr);    
	
	if (NULL == context) {
		return 0;
	}
	
	// 利用xpath查询得到结果集
	result = xmlXPathEvalExpression(xpath, context);
	xmlXPathFreeContext(context);
	
	// 结果对象为空
	if (NULL == result) {
		return 0;
	}
	
	// 结果对象的nodeset为空
	if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
		xmlXPathFreeObject(result);
		return 0;
	}
	count = result->nodesetval->nodeNr;
	xmlXPathFreeObject(result);
	return count;
}

/**
 * 针对xpath结果集中仅有一个元素的情况：添加一个childnode
 * @param docptr
 * @param xpath语句
 * @param childnode
 * @return 成功返回TRUE，失败返回FALSE
 */
CHASSIS_API gboolean xml_xpath_onenodeset_addchild(const xmlDocPtr docptr, const xmlChar *xpath, xmlNodePtr childnode) {
	xmlXPathObjectPtr  result = NULL;
	result = xml_xpath_get_nodeset(docptr, xpath);
	if (NULL == result) {
		return FALSE;
	}
	
	if (result->nodesetval->nodeNr != 1) {
		xmlXPathFreeObject(result);
		result = NULL;
		return FALSE;
	}
	
	if (NULL == xmlAddChild(result->nodesetval->nodeTab[0], childnode)) {
		xmlXPathFreeObject(result);
		result = NULL;
		return FALSE;
	}
	// 在此释放result对象
	xmlXPathFreeObject(result);
	result = NULL;
	return TRUE;
}

/**
 * 针对xpath结果集中仅有一个元素的情况：删除这个元素
 * @param docptr
 * @param xpath语句
 * @return 成功返回TRUE，失败返回FALSE
 */
CHASSIS_API gboolean xml_xpath_onenodeset_delmyself(const xmlDocPtr docptr, const xmlChar *xpath) {
	xmlXPathObjectPtr  result = NULL;
	result = xml_xpath_get_nodeset(docptr, xpath);
	if (NULL == result) {
		return FALSE;
	}
	
	if (result->nodesetval->nodeNr != 1) {
		xmlXPathFreeObject(result);
		result = NULL;
		return FALSE;
	}
	
	xmlUnlinkNode(result->nodesetval->nodeTab[0]);
	xmlFreeNode(result->nodesetval->nodeTab[0]);
	result->nodesetval->nodeTab[0] = NULL;
	xmlXPathFreeObject(result);
	result = NULL;
	return TRUE;
}

/**
 * 对于xpath结果集中所有节点，如果其子节点是text节点，且匹配text_content字符串，则删除
 * @param docptr
 * @param xpath语句
 * @param text_content
 * @return 成功返回TRUE，失败返回FALSE
 */
CHASSIS_API gboolean xml_xpath_nodeset_delchild_matchtext(const xmlDocPtr docptr, const xmlChar *xpath, const xmlChar *text_content) {
	xmlXPathObjectPtr  result = NULL;
	xmlChar *keyword = NULL;
	int i;
	result = xml_xpath_get_nodeset(docptr, xpath);
	if (NULL == result) {
		return FALSE;
	}
	
	for (i = 0; i < result->nodesetval->nodeNr; i++) {
		keyword = xmlNodeGetContent(result->nodesetval->nodeTab[i]->xmlChildrenNode);   
		// 如果相等，则删除相应节点
		if (!xmlStrcasecmp(keyword, text_content)) {
			xmlUnlinkNode(result->nodesetval->nodeTab[i]);
			xmlFreeNode(result->nodesetval->nodeTab[i]);
			result->nodesetval->nodeTab[i] = NULL;
		}
		xmlFree(keyword);
		keyword = NULL;
	}
	
	xmlXPathFreeObject(result);
	result = NULL;
	return TRUE;
}

/**
 * 对于xpath结果集中所有节点，如果其子节点是text节点，且匹配text_content字符串，则返回TRUE
 * @param docptr
 * @param xpath语句
 * @param text_content
 * @return 成功返回TRUE，失败返回FALSE
 */
CHASSIS_API gboolean xml_xpath_nodeset_ischild_matchtext(const xmlDocPtr docptr, const xmlChar *xpath, const xmlChar *text_content) {
	xmlXPathObjectPtr  result = NULL;
	xmlChar *keyword = NULL;
	gboolean ret = FALSE;
	int i;
	result = xml_xpath_get_nodeset(docptr, xpath);
	if (NULL == result) {
		return FALSE;
	}
	
	for (i = 0; i < result->nodesetval->nodeNr; i++) {
		keyword = xmlNodeGetContent(result->nodesetval->nodeTab[i]->xmlChildrenNode);   
		// 如果相等，ret = TRUE
		if (!xmlStrcasecmp(keyword, text_content)) {
			xmlFree(keyword);
			keyword = NULL;
			ret = TRUE;
			break;
		}
		xmlFree(keyword);
		keyword = NULL;
	}
	
	xmlXPathFreeObject(result);
	result = NULL;
	return ret;
}

/**
 * 对于xpath结果集中所有节点，如果其子节点是text节点，且匹配text_content字符串，则返回TRUE
 * @param docptr
 * @param xpath语句
 * @param text_content
 * @return 成功返回TRUE，失败返回FALSE
 */
CHASSIS_API gboolean xml_xpath_onenodeset_ischild_matchtext(const xmlDocPtr docptr, const xmlChar *xpath, const xmlChar *text_content) {
	xmlXPathObjectPtr  result = NULL;
	xmlChar *keyword = NULL;
	gboolean ret = FALSE;
	result = xml_xpath_get_nodeset(docptr, xpath);
	if (NULL == result) {
		return FALSE;
	}
	
	if (result->nodesetval->nodeNr != 1) {
		xmlXPathFreeObject(result);
		result = NULL;
		return FALSE;
	}
	keyword = xmlNodeGetContent(result->nodesetval->nodeTab[0]->xmlChildrenNode);   
	// 如果相等，ret = TRUE
	if (!xmlStrcasecmp(keyword, text_content)) {
		ret = TRUE;
	}
	xmlFree(keyword);
	keyword = NULL;
	
	xmlXPathFreeObject(result);
	result = NULL;
	return ret;
}

/**
 * 针对xpath结果集中仅有一个元素的情况：查到这个元素的child textnode并将结果返回
 * @param docptr
 * @param xpath语句
 * @return 成功返回字符串，否则返回NULL，返回的字符串内存需由caller释放
 */
CHASSIS_API xmlChar *xml_xpath_onenodeset_getchild_text(const xmlDocPtr docptr, const xmlChar *xpath) {
	xmlXPathObjectPtr  result = NULL;
	xmlNodePtr childNode = NULL;
	xmlChar *ret = NULL;
	
	result = xml_xpath_get_nodeset(docptr, xpath);
	if (NULL == result) {
		return NULL;
	}
	
	if (result->nodesetval->nodeNr != 1) {
		xmlXPathFreeObject(result);
		result = NULL;
		return NULL;
	}
	childNode = result->nodesetval->nodeTab[0]->xmlChildrenNode;
	if (NULL == childNode) {
		xmlXPathFreeObject(result);
		result = NULL;
		return NULL;
	}
	ret = xmlNodeGetContent(childNode);
	
	xmlXPathFreeObject(result);
	result = NULL;
	return ret;
}

/**
 * 针对xpath结果集中仅有一个元素的情况：查到这个元素的child textnode，并将其content改成指定字符串
 * @param docptr
 * @param xpath语句
 * @param 指定字符串
 * @return 成功返回TRUE，失败返回FALSE
 */
CHASSIS_API gboolean xml_xpath_onenodeset_setchild_text(const xmlDocPtr docptr, const xmlChar *xpath, const xmlChar *content) {
	xmlXPathObjectPtr  result = NULL;
	xmlNodePtr childNode = NULL;
	
	result = xml_xpath_get_nodeset(docptr, xpath);
	if (NULL == result) {
		return FALSE;
	}
	
	if (result->nodesetval->nodeNr != 1) {
		xmlXPathFreeObject(result);
		result = NULL;
		return FALSE;
	}
	childNode = result->nodesetval->nodeTab[0]->xmlChildrenNode;
	if (NULL == childNode) {
		xmlXPathFreeObject(result);
		result = NULL;
		return FALSE;
	}
	xmlNodeSetContent(childNode, content);
	
	xmlXPathFreeObject(result);
	result = NULL;
	return TRUE;
}
