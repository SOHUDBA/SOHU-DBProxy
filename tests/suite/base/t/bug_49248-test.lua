--[[ $%BEGINLICENSE%$
 Copyright (c) 2012, Oracle and/or its affiliates. All rights reserved.

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

 $%ENDLICENSE%$ --]]

---
-- if we receive a "trigger_bug", send a "get_err_packet" to the mock
--
-- trying to access the .resultset structure of the resulting ERR packet shouldn't 
-- lead to a crash
--


function read_query( packet )
	if packet:byte() == proxy.COM_QUERY then
		if packet:sub(2) == "trigger_bug" then
			proxy.queries:append(1, string.char(proxy.COM_QUERY) .. "get_err_packet" , {resultset_is_needed = true}) 
			return proxy.PROXY_SEND_QUERY
		end
	end
end
 

function read_query_result ( inj )
	assert(inj.resultset.query_status == 255) -- we got an error-packet
	local fields = inj.resultset.fields       -- crashes if not fixed
	assert(fields[0] == nil)
end

