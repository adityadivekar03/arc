import dkim
import email
import re
import spf


def spfverify( raw_message):
	HELO = None
	mailfrom = None
	client_ip = None
	msg = email.message_from_string(raw_message)
	raw_msg = raw_message
	mailfrom = email.utils.parseaddr(msg['Return-Path'])[1]
	regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
                    "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
                    "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))
	headers, body = dkim.rfc822_parse(raw_msg)
	sigheaders = [(x,y) for x,y in headers if x.lower() == b"received"]
	for i in range(0,len(sigheaders)):
		sig = sigheaders[i]
		if sig[1].find('from')!=-1:
			start = sig[1].find('from')
			end = sig[1].find('(')
			substr = sig[1][start:end]
			HELO = substr[start+4:end].strip()
			if HELO is not None:
				# Extract the client-ip from the Received field
				client_ip = re.search(r'(?<=\[)[^\[\]]*(?=\])', sig[1])
				if client_ip is not None:
					client_ip = client_ip.group()
			break
	# Query the spf record and perform spf verification
	result = None
	if HELO is not None and client_ip is not None:
		result = spf.check2(client_ip, mailfrom, HELO)
	if result is None:
		res = 'none'
	elif result[0] == 'fail' or result[0] == 'permerror' or result[0] == 'softfail' or result[0] == 'temperror':
		res = 'fail'
	else:
		res = 'pass'
	return res
