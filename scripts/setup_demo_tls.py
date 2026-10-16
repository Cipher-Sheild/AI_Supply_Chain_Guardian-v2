"""Prepare a localhost demonstration certificate in a private deployment directory.

Remote production deployments should mount their organization's trusted certs.
This self-signed local certificate is trusted only by clients given its CA file.
"""
import argparse
import ipaddress
import os
from datetime import datetime,timedelta,timezone
from pathlib import Path


def main():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=Path(__file__).resolve().parents[1]/'.data/production-pass/tls')
    args=parser.parse_args();directory=args.directory.resolve()
    directory.parent.mkdir(parents=True,exist_ok=True);directory.parent.chmod(0o700)
    directory.mkdir(exist_ok=True);directory.chmod(0o755)
    key_path=directory/'server.key';cert_path=directory/'server.crt'
    if key_path.exists() or cert_path.exists():
        if not key_path.exists() or not cert_path.exists():raise ValueError('Incomplete existing TLS pair; refusing to overwrite')
        print('Existing demo TLS pair retained.');return
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Guardian localhost demonstration')])
    now=datetime.now(timezone.utc)
    certificate=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
        .not_valid_after(now+timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1')),x509.IPAddress(ipaddress.ip_address('::1'))]),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        .sign(key,hashes.SHA256()))
    # The enclosing deployment directory is 0700. Files are readable by the
    # isolated unprivileged nginx UID through its read-only bind mount.
    for path,raw in [(key_path,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())),
                     (cert_path,certificate.public_bytes(serialization.Encoding.PEM))]:
        descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
        with os.fdopen(descriptor,'wb') as stream:stream.write(raw)
        path.chmod(0o644)
    print('Local demonstration TLS pair prepared; certificate:',cert_path)


if __name__=='__main__':main()
