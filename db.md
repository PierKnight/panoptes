# Informal Description
## Tables

- **client**:
    - `id` (UUID)
    - `name` (string)

- **web_domains**:
    - `id` (UUID)
    - `name` (string)
    - `client_id` (UUID) — foreign key to `client.client_id`

- **mail_domains**:
    - `id` (UUID)
    - `name` (string)
    - `client_id` (UUID) — foreign key to `client.client_id`

- **subdomains**:
    - `id` (UUID)
    - `name` (string)
    - `web_domain_id` (UUID)

- **hosts**:
    - `id` (UUID)
    - `ip_address` (string)
    - `asn` (string) — e.g., `AS12345`
    - `isp` (string) — e.g., `GOOGLE LLC`
    - `exposed_ports` (JSON) — [example](#exposed_ports)
    - `cve` (JSON) — [example](#cve)

- **subdomains_hosts**:
    - `id` (UUID)
    - `host_id` (UUID) — foreign key to `hosts.id`
    - `subdomain_id` (UUID) — foreign key to `subdomains.id`

- **ip_abuses**:
    - `id` (UUID)
    - `date_reported` (date)
    - `comment` (string)
    - `categories` (JSON) — e.g., `["spam", "malware"]`
    - `host_id` (UUID) — foreign key to `hosts.id`

- **dns_records**:
    - `id` (UUID)
    - `records` (JSON) — e.g., [example](#dns_records)

- **dmarc_checks**:
    - `id` (UUID)
    - `record` (string) — e.g., `v=DMARC1; p=none; rua=mailto:
    - `image` (blob) — base64 encoded image of the DMARC record
    - `failed` (JSON) — e.g., [example](#failed_warnings_passed)
    - `warnings` (JSON) — e.g., [example](#failed_warnings_passed)
    - `passed` (JSON) — e.g., [example](#failed_warnings_passed)
    - `web_domain_id` (UUID) — foreign key to `web_domains.id`

- **spf_checks**:
    - `id` (UUID)
    - `record` (string) — e.g., `v=spf1 include:_spf.example.com ~all`
    - `image` (blob) — e.g., base64 encoded image of SPF record
    - `failed` (JSON) — e.g., [example](#failed_warnings_passed)
    - `warnings` (JSON) — e.g., [example](#failed_warnings_passed)
    - `passed` (JSON) — e.g., [example](#failed_warnings_passed)
    - `web_domain_id` (UUID) — foreign key to `web_domains.id`
 
- **emails**:
    - `id` (UUID)
    - `address` (string)
    - `mail_domain_id` (UUID) — foreign key to `mail_domains.id`

- **data_breaches**:
    (To be populated as new data breaches are discovered via API responses)
    - `id` (UUID)
    - `title` (string)
    - `date` (date)
    - `data_classes` (JSON) — e.g., `["Email addresses", "Passwords"]`
    - `description` (string)

- **emails_data_breaches**:
    (An instance of this table represents an email being part of a data breach)
    - `id` (UUID)
    - `email_id` (UUID) — foreign key to `emails.id`
    - `data_breach_id` (UUID) — foreign key to `data_breaches.id`

- **data_leaks**:
    (An instance of this table represents a leak)
    - `id` (UUID)
    - `leak` (string) — e.g., `info@example.com:password`
    - `email_id` (UUID) — foreign key to `emails.id`

- **missing_http_headers**:
    (An instance of this table represents a missing HTTP header)
    - `id` (UUID)
    - `missing_headers` (JSON) — e.g., `["X-Content-Type-Options", "X-Frame-Options"]`
    - `web_domain_id` (UUID) — foreign key to `web_domains.id`

- **technologies**:
    - `id` (UUID)
    - `name` (string) — e.g., `Apache`, `Nginx`
    - `version` (string) — e.g., `2.4.58`
    - `category` (string) — e.g., `Web Server`, `Database`
    - `web_domain_id` (UUID) — foreign key to `web_domains.id`

- **ssl_certificates**:
    - `id` (UUID)
    - `common_name` (string) — e.g., `example.com`
    - `organization` (string) — e.g., `Example Inc.`
    - `issuer` (string) — e.g., `Let's Encrypt`
    - `valid_from` (date)
    - `valid_to` (date)
    - `sans` (JSON) — e.g., `["example.com", "www.example.com"]`
    - `location` (JSON) — e.g., `["Roma", "Lazio", "IT"]`
    - `serial_number` (string) — e.g., `1234567890abcdef`
    - `signature_algorithm` (string) — e.g., `SHA256withRSAEncryption`
    - `image` (blob) — base64 encoded image of the SSL certificate
    - `web_domain_id` (UUID) — foreign key to `web_domains.id`


## Examples
### exposed_ports: 
```JSON
{
    "22": {
        "protocol": "SSH",
        "os": "Linux",
        "product": "OpenSSH",
        "transport": "tcp",
        "version": "9.6p1 Ubuntu 3ubuntu13.11",
        "name": "22/tcp/OpenSSH/9.6p1 Ubuntu 3ubuntu13.11"
        
    },
    "80": {
        "protocol": "HTTP",
        "os": null,
        "product": "Apache",
        "version": "2.4.58",
        "transport": "tcp",
        "name": "80/tcp/Apache/2.4.58"
    },
    "443": {
        "os": null,
        "product": "Apache httpd",
        "transport": "tcp",
        "version": "2.4.58",
        "name": "443/tcp/Apache httpd/2.4.58"
    }
}
```

### cve: 
```JSON
{
    "CVE-2023-1234": {
        "summary": "Description of CVE-2023-1234",
        "cvs"
    },
    "CVE-2023-5678": {
        "summary": "Description of CVE-2023-5678",
        "severity": "medium"
    }
}
```

### dns_records: 
```JSON
{
    "a": {
        "host": "mx.example.com",
        "ips": [
            {
                "asn": "12345",
                "asn_name": "ARUBA-ASN, IT",
                "ip": "REDACTED"
            }
        ]
    },
    "cname": {},
    "mx": {
        "host": "10 mx.example.com",
        "ips": [
            {
                "asn": "12345",
                "asn_name": "ARUBA-ASN, IT",
                "ip": "REDACTED"
            }
        ]
    },
    "ns": {
        "host": "dns3.arubadns.net",
        "ips": [
            {
                "asn": "12345",
                "asn_name": "ARUBA-ASN, IT",
                "ip": "REDACTED"
            }
        ]
    },
    "total_a_recs": {},
    "txt": [
        "\"MS=ms00000000\"",
        "\"3600\"",
        "\"v=spf1 include:_spf.aruba.it ~all\"",
        "\"@\"",
    ]
}
```

### failed_warnings_passed:
```JSON
[
    {
        "Name": "DMARC Policy Not Enabled",
        "Info": "DMARC Quarantine/Reject policy not enabled"
    }
]
```

# DDL