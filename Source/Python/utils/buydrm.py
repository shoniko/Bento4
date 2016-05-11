import requests
from xml.sax.saxutils import unescape
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET
import uuid
import binascii

def GetBuyDRMKey(UserKey):
	payload = """<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
	<soap:Header/>
	<soap:Body>
	<RequestEncryptionInfo xmlns="http://tempuri.org/"><ServerKey>7FAA278B-EBC2-4625-9160-913EEDE73D3A</ServerKey>
	<RequestXml>""" + escape("""<KeyOSEncryptionInfoRequest><APIVersion>5.0.0.2</APIVersion> 
	<DRMType>smooth</DRMType>
	<EncoderVersion>BuyDRM Bento v1.0a</EncoderVersion>
	<UserKey>""" + UserKey + """</UserKey> 
	<KeyID>""" + str(uuid.uuid4()) + """</KeyID>
	<ContentID>""" + str(uuid.uuid4()) + """</ContentID> 
	<fl_GeneratePRHeader>true</fl_GeneratePRHeader>
	<MediaID>""" + str(uuid.uuid4()) + """</MediaID>
	</KeyOSEncryptionInfoRequest>""") + "</RequestXml></RequestEncryptionInfo></soap:Body></soap:Envelope>"

	headers = {"SOAPAction" : "http://tempuri.org/ISmoothPackager/RequestEncryptionInfo", "Content-Type" : "text/xml", }

	r = requests.post("http://packager.licensekeyserver.com/pck", data=payload, headers=headers)

	responseTree = ET.XML(unescape(r.text))
	encryptionInfoResponse = responseTree[0][0][0][0]
	message = encryptionInfoResponse[1]
	status = encryptionInfoResponse[0]
	if status.text == '0':
		keyID = encryptionInfoResponse[3]
		contentKey = encryptionInfoResponse[4]
		header = encryptionInfoResponse[9]
		print "KID:" + uuid.UUID(keyID.text).bytes.encode('base64')
		print "Key:" + contentKey.text
		return uuid.UUID(keyID.text).hex + ":" + binascii.a2b_base64(contentKey.text).encode('hex_codec'), header.text.encode('utf-16-le')
	else:
		return message.text, ""