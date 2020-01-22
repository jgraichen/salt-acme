# -*- coding: utf-8 -*-

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# def test_sign(runners):
#     key = ec.generate_private_key(curve=ec.SECP192R1, backend=default_backend())

#     subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"example.org")])
#     extension = x509.Extension(
#         x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
#         False,
#         x509.SubjectAlternativeName(
#             [x509.DNSName(u"www.example.org"), x509.DNSName(u"example.org")]
#         ),
#     )

#     csr = x509.CertificateSigningRequestBuilder(subject, [extension]).sign(
#         key, hashes.SHA384(), default_backend()
#     )

#     pem = csr.public_bytes(serialization.Encoding.PEM).decode()

#     ret = runners["acme.sign"](pem)

#     assert ret['text'] == 'acb'
