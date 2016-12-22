from .version import __version__  # noqa: F401

import json
import M2Crypto
import M2Crypto.SMIME
import re

# This is the AWS Public Certificate for all non-gov regions
AWS_PUBLIC_CERT = M2Crypto.X509.load_cert_string("""
-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----
""")


# Format base64 document as PEM for M2Crypto
def pem_format(doc, type='PKCS7'):
  # remove empty lines and line breaks
  doc = ''.join(list(filter(bool, doc.splitlines())))

  # remove any PEM header/footer, we will replace them later
  doc = re.sub('-----[^-]+-----', '', doc)

  # wrap the data at a uniform width
  wrap = 64
  doc = "\n".join([doc[0 + i:wrap + i] for i in range(0, len(doc), wrap)])

  # return with PEM header/footer
  return "-----BEGIN {}-----\n{}\n-----END {}-----".format(type, doc, type)


# Verify a PKCS7 signed instance identity document and return the body
def verify_pkcs7(document):
  pem = pem_format(document, 'PKCS7')
  smime = M2Crypto.SMIME.SMIME()

  stack = M2Crypto.X509.X509_Stack()
  stack.push(AWS_PUBLIC_CERT)
  smime.set_x509_stack(stack)

  store = M2Crypto.X509.X509_Store()
  store.add_x509(AWS_PUBLIC_CERT)
  smime.set_x509_store(store)

  p7bio = M2Crypto.BIO.MemoryBuffer(pem)
  p7 = M2Crypto.SMIME.load_pkcs7_bio(p7bio)

  try:
    return json.loads(smime.verify(p7))
  except M2Crypto.SMIME.PKCS7_Error as e:
    raise M2Crypto.SMIME.PKCS7_Error("Could not verify identity document:", e)
