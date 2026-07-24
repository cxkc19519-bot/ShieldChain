import argparse
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Define the URN namespace as per the paper
# The format for AgentId is "urn:saga:agent:{owner_id}:{agent_name}"
# The format for UserId is "urn:saga:user:{user_email}"
# The format for Provider is "urn:saga:provider:{provider_domain}"

def _generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()

def _save_key_and_cert(
    out_dir: Path, name: str, key: Ed25519PrivateKey, cert: x509.Certificate
) -> None:
    key_path = out_dir / f"{name}_key.pem"
    cert_path = out_dir / f"{name}_cert.pem"
    
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"Generated {name} certificate and key at {out_dir}")

def create_root_ca(out_dir: Path) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    key = _generate_private_key()
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SAGA Test Root CA"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, algorithm=None)
    )
    
    _save_key_and_cert(out_dir, "ca", key, cert)
    return key, cert

def create_leaf_cert(
    out_dir: Path,
    name: str,
    ca_key: Ed25519PrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    urn: str,
    is_server: bool = False,
    is_client: bool = False,
    dns_name: str | None = None,
) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    key = _generate_private_key()
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    
    # Add EKU
    ekus = []
    if is_server:
        ekus.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if is_client:
        ekus.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        
    if ekus:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
        
    # Add SANs
    sans: list[x509.GeneralName] = [x509.UniformResourceIdentifier(urn)]
    if dns_name:
        sans.append(x509.DNSName(dns_name))
        
    builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
    )
    
    cert = builder.sign(ca_key, algorithm=None)
    
    _save_key_and_cert(out_dir, name, key, cert)
    
    # Also write a chained cert file for convenience
    chain_path = out_dir / f"{name}_fullchain.pem"
    with open(chain_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
    return key, cert

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SAGA Test Certificates")
    parser.add_argument("--out", type=Path, default=Path("tests/fixtures/pki"), help="Output directory")
    args = parser.parse_args()
    
    out_dir: Path = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating PKI in {out_dir}...")
    
    ca_key, ca_cert = create_root_ca(out_dir)
    
    # 1. Provider (Server Auth only, with localhost DNS for testing)
    create_leaf_cert(
        out_dir=out_dir,
        name="provider",
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name="saga.example.com",
        urn="urn:saga:provider:saga.example.com",
        is_server=True,
        is_client=False,
        dns_name="localhost",
    )
    
    # 2. Agent A (Server + Client Auth, with localhost DNS for testing)
    create_leaf_cert(
        out_dir=out_dir,
        name="agent_a",
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name="alice:agent-a",
        urn="urn:saga:agent:alice:agent-a",
        is_server=True,
        is_client=True,
        dns_name="localhost",
    )
    
    # 3. Agent B (Client Auth)
    create_leaf_cert(
        out_dir=out_dir,
        name="agent_b",
        ca_key=ca_key,
        ca_cert=ca_cert,
        common_name="bob:agent-b",
        urn="urn:saga:agent:bob:agent-b",
        is_server=True,  # Agents can technically receive or initiate, so giving both
        is_client=True,
        dns_name="localhost",
    )
    
    print("Done!")

if __name__ == "__main__":
    main()
