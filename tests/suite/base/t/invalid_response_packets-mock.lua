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

local proto = assert(require("mysql.proto"))

counter = counter or 1

function connect_server()
	-- emulate a server
	proxy.response = {
		type = proxy.MYSQLD_PACKET_RAW,
		packets = {
			proto.to_challenge_packet({})
		}
	}
	return proxy.PROXY_SEND_RESULT
end

function read_query(packet)
	if packet:byte() == 0x02 then
		proxy.response = {
			type = proxy.MYSQLD_PACKET_OK
		}
		return proxy.PROXY_SEND_RESULT
	elseif packet:byte() == 0x11 then
		counter = counter or 1
		-- COM_CHANGE_USER
		if counter == 1 then
			-- mock a "change to the old password"
			proxy.response = {
				type = proxy.MYSQLD_PACKET_RAW,
				packets = {
					"\254"
				}
			}
		elseif counter == 2 then
			-- mock a invalid initial response
			proxy.response = {
				type = proxy.MYSQLD_PACKET_RAW,
				packets = {
					"\001"
				}
			}
		else
			-- check we handle a OK nicely
			proxy.response = {
				type = proxy.MYSQLD_PACKET_OK,
			}
		end
		return proxy.PROXY_SEND_RESULT
	end

	proxy.response = {
		type = proxy.MYSQLD_PACKET_ERR,
		errmsg = ("invalid command: %d"):format(packet:byte())
	}
	return proxy.PROXY_SEND_RESULT
end

