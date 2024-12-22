from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

def generate_private_key():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def generate_certificate(private_key, common_name):
    # Generate a self-signed X.509 certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Validity period of the certificate
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=365)  # 1-year validity

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    return certificate

def save_key_and_certificate(private_key, certificate, key_filename, cert_filename):
    # Save private key
    with open(key_filename, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save certificate
    with open(cert_filename, "wb") as cert_file:
        cert_file.write(
            certificate.public_bytes(encoding=serialization.Encoding.PEM)
        )

if __name__ == "__main__":
    # Generate RSA private key
    private_key = generate_private_key()

    # Generate self-signed certificate
    common_name = "mydomain.com"
    certificate = generate_certificate(private_key, common_name)

    # Save private key and certificate to files
    save_key_and_certificate(private_key, certificate, "private_key.pem", "certificate.pem")

    print("Private key and certificate generated successfully!")
