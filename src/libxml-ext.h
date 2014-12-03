/*
 * libxml-ext.h
 *
 *  Created on: 2013-8-21
 *      Author: zhenfan
 */

#ifndef LIBXML_EXT_H_
#define LIBXML_EXT_H_
/**
 * @author sohu-inc.com
 * 该文件是实现对libxml中xml文件接口的封装,
 * 主要实现的对外功能接口包括：
 *  1. xml 文件节点的遍历
 *  2. 通过某个属性获取某个节点
 *  3. 修改某个节点的对应的元素的取值（通过属性或另一个元素值定位）
 *  4. 保存修改之xml文件
 */
#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlstring.h>
#include <glib.h>
#include "chassis-exports.h"

CHASSIS_API xmlDocPtr xml_get_file_ptr(const gchar *xmlFile);

CHASSIS_API xmlNodePtr xml_get_file_node_root(const xmlDocPtr docptr);

CHASSIS_API xmlXPathObjectPtr xml_xpath_get_nodeset(const xmlDocPtr docptr, const xmlChar *xpath);

CHASSIS_API gint xml_xpath_get_nodeset_count(const xmlDocPtr docptr, const xmlChar *xpath);

CHASSIS_API gboolean xml_xpath_onenodeset_addchild(const xmlDocPtr docptr, const xmlChar *xpath, xmlNodePtr childnode); 

CHASSIS_API gboolean xml_xpath_onenodeset_delmyself(const xmlDocPtr docptr, const xmlChar *xpath);

CHASSIS_API gboolean xml_xpath_nodeset_delchild_matchtext(const xmlDocPtr docptr, const xmlChar *xpath, const xmlChar *text_content);

CHASSIS_API gboolean xml_xpath_nodeset_ischild_matchtext(const xmlDocPtr docptr, const xmlChar *xpath, const xmlChar *text_content);

CHASSIS_API gboolean xml_xpath_onenodeset_ischild_matchtext(const xmlDocPtr docptr, const xmlChar *xpath, const xmlChar *text_content);

CHASSIS_API xmlChar *xml_xpath_onenodeset_getchild_text(const xmlDocPtr docptr, const xmlChar *xpath);

CHASSIS_API gboolean xml_xpath_onenodeset_setchild_text(const xmlDocPtr docptr, const xmlChar *xpath, const xmlChar *content);
								
#endif /* LIBXML_EXT_H_ */
