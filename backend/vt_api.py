import requests as req
from json import JSONDecoder
def get_report(ipv4: str):
    url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(ipv4)
    response = req.get(url, {"accept": "application/json"})
    return JSONDecoder().decode(response.text)


API_KEY: str
# stop list subject_key_identifier, subject:CN, as_owner
response_example = {
    "data": {
        "id": "94.159.104.104",
        "type": "ip_address",
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/94.159.104.104"
        },
        "attributes": {
            "regional_internet_registry": "RIPE NCC",
            "jarm": "27d27d27d3fd27d1dc41d41d000000937221baefa0b90420c8e8e41903f1d5",
            "asn": 215730,
            "last_https_certificate_date": 1739068842,
            "last_https_certificate": {
                "cert_signature": {
                    "signature_algorithm": "sha256RSA",
                    "signature": "47238482f756337735ff194a8dd85999a9abb3f132112cb6ffce5e77b5f0166c8ab972917601e734b474c4688a0c87187b3b3f0d337684907c247525ded01c2c2ff26f17fb47739de8e82341483ccf3b4c36e3ec0d2c6a3c0be099504433752e933e0e1ea3edd82e8ea90b2db2f0fa125530ae33842466d13eed93ddc8284b69a5a8f28ebb1ac8c34ae772b8d5ab443295df9de8112d361fdbfd46763c11a73b415df33acc66ab5221b7433bd189c9ee6cf0fddc3f95ddef7f42c6d5ebea675cd60aab7567e456dcb0ab2da4a29f4141032f9a6bffdb27180ffb17d2792b74865ec787326498a75be054216e0ed9bd5745745ea6032af7d15814bc85bcb946fe"
                },
                "extensions": {
                    "authority_key_identifier": {
                        "keyid": "5168ff90af0207753cccd9656462a212b859723b"
                    },
                    "subject_key_identifier": "1481b9be95f0c9b741f3b7ca1a66a83179fb7399",
                    "subject_alternative_name": [
                        "yahoo.com",
                        "tw.rd.yahoo.com",
                        "s.yimg.com",
                        "mbp.yimg.com",
                        "hk.rd.yahoo.com",
                        "fr-ca.rogers.yahoo.com",
                        "ddl.fp.yahoo.com",
                        "ca.rogers.yahoo.com",
                        "ca.my.yahoo.com",
                        "brb.yahoo.net",
                        "add.my.yahoo.com",
                        "*.yahoo.com",
                        "*.www.yahoo.com",
                        "*.media.yahoo.com",
                        "*.att.yahoo.com",
                        "*.amp.yimg.com"
                    ],
                    "certificate_policies": [
                        "2.23.140.1.2.2"
                    ],
                    "key_usage": [
                        "digitalSignature",
                        "keyAgreement"
                    ],
                    "extended_key_usage": [
                        "serverAuth",
                        "clientAuth"
                    ],
                    "crl_distribution_points": [
                        "http://crl3.digicert.com/sha2-ha-server-g6.crl",
                        "http://crl4.digicert.com/sha2-ha-server-g6.crl"
                    ],
                    "ca_information_access": {
                        "OCSP": "http://ocsp.digicert.com",
                        "CA Issuers": "http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt"
                    },
                    "CA": False,
                    "1.3.6.1.4.1.11129.2.4.2": "0482016a01680076004e75a3275c9a10c3385b6cd4df3f52eb1df0e08e1b8d69"
                },
                "validity": {
                    "not_after": "2025-06-11 23:59:59",
                    "not_before": "2024-12-17 00:00:00"
                },
                "size": 1781,
                "version": "V3",
                "public_key": {
                    "algorithm": "EC",
                    "ec": {
                        "oid": "secp256r1",
                        "pub": "3059301306072a8648ce3d020106082a8648ce3d03010703420004b09057f2c45c6ac58b6857f1b99b488efe3994543fddd613973e7386b4bcf880b00464574fea7d358676378821c62f030f970087104d3cd0a62e4ba500cffc37"
                    }
                },
                "thumbprint_sha256": "34e430c23d8aa378c0b3ce9dad0737eafd98ae523799414fde30d157e6d8e091",
                "thumbprint": "6f19a796a3a3efafabe6189680a35a4918263b9a",
                "serial_number": "ef1268579565ce0a26b131988c9b88a",
                "issuer": {
                    "C": "US",
                    "O": "DigiCert Inc",
                    "OU": "www.digicert.com",
                    "CN": "DigiCert SHA2 High Assurance Server CA"
                },
                "subject": {
                    "C": "US",
                    "ST": "New York",
                    "L": "New York",
                    "O": "Yahoo Holdings Inc.",
                    "CN": "yahoo.com"
                }
            },
            "whois": "inetnum: 94.159.104.0 - 94.159.111.255\nnetname: H2NEXUS\ncountry: DE\ndescr: H2.NEXUS Frankfurt Network\ngeoloc: 50.0379 8.5622\norg: ORG-HL357-RIPE\nremarks: H2.NEXUS Frankfurt Network\nadmin-c: HL5106-RIPE\ntech-c: HL5106-RIPE\nstatus: ASSIGNED PA\nmnt-by: NHT-MNT\nmnt-by: NEXUS-MNT\ncreated: 2024-09-16T14:06:29Z\nlast-modified: 2024-09-16T14:06:29Z\nsource: RIPE\norganisation: ORG-HL357-RIPE\norg-name: H2NEXUS LTD\norg-type: OTHER\naddress: 71-75 Shelton Street, Covent Garden, London, United Kingdom, WC2H 9JQ\ncountry: GB\nabuse-c: HL5106-RIPE\nmnt-ref: NHT-MNT\nmnt-ref: Renets-mnt\nmnt-ref: NEXUS-MNT\nmnt-by: NEXUS-MNT\ncreated: 2024-09-10T21:42:41Z\nlast-modified: 2024-09-28T20:52:04Z\nsource: RIPE # Filtered\nrole: H2NEXUS LTD\naddress: 71-75, Shelton Street, Covent Garden, London, United Kingdom, WC2H 9JQ\nabuse-mailbox: abuse@h2.nexus\nnic-hdl: HL5106-RIPE\nmnt-by: NEXUS-MNT\ncreated: 2024-01-10T16:19:44Z\nlast-modified: 2024-09-10T21:41:50Z\nsource: RIPE # Filtered\nroute: 94.159.96.0/20\norigin: AS215730\nmnt-by: NHT-MNT\ncreated: 2024-09-25T09:40:42Z\nlast-modified: 2024-09-25T09:40:42Z\nsource: RIPE\n",
            "last_analysis_results": {
                "Acronis": {
                    "method": "blacklist",
                    "engine_name": "Acronis",
                    "category": "harmless",
                    "result": "clean"
                },
                "0xSI_f33d": {
                    "method": "blacklist",
                    "engine_name": "0xSI_f33d",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Abusix": {
                    "method": "blacklist",
                    "engine_name": "Abusix",
                    "category": "harmless",
                    "result": "clean"
                },
                "ADMINUSLabs": {
                    "method": "blacklist",
                    "engine_name": "ADMINUSLabs",
                    "category": "harmless",
                    "result": "clean"
                },
                "Axur": {
                    "method": "blacklist",
                    "engine_name": "Axur",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Criminal IP": {
                    "method": "blacklist",
                    "engine_name": "Criminal IP",
                    "category": "suspicious",
                    "result": "suspicious"
                },
                "AILabs (MONITORAPP)": {
                    "method": "blacklist",
                    "engine_name": "AILabs (MONITORAPP)",
                    "category": "harmless",
                    "result": "clean"
                },
                "AlienVault": {
                    "method": "blacklist",
                    "engine_name": "AlienVault",
                    "category": "harmless",
                    "result": "clean"
                },
                "alphaMountain.ai": {
                    "method": "blacklist",
                    "engine_name": "alphaMountain.ai",
                    "category": "suspicious",
                    "result": "suspicious"
                },
                "AlphaSOC": {
                    "method": "blacklist",
                    "engine_name": "AlphaSOC",
                    "category": "suspicious",
                    "result": "suspicious"
                },
                "Antiy-AVL": {
                    "method": "blacklist",
                    "engine_name": "Antiy-AVL",
                    "category": "harmless",
                    "result": "clean"
                },
                "ArcSight Threat Intelligence": {
                    "method": "blacklist",
                    "engine_name": "ArcSight Threat Intelligence",
                    "category": "malicious",
                    "result": "malware"
                },
                "AutoShun": {
                    "method": "blacklist",
                    "engine_name": "AutoShun",
                    "category": "undetected",
                    "result": "unrated"
                },
                "benkow.cc": {
                    "method": "blacklist",
                    "engine_name": "benkow.cc",
                    "category": "harmless",
                    "result": "clean"
                },
                "Bfore.Ai PreCrime": {
                    "method": "blacklist",
                    "engine_name": "Bfore.Ai PreCrime",
                    "category": "undetected",
                    "result": "unrated"
                },
                "BitDefender": {
                    "method": "blacklist",
                    "engine_name": "BitDefender",
                    "category": "harmless",
                    "result": "clean"
                },
                "Bkav": {
                    "method": "blacklist",
                    "engine_name": "Bkav",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Blueliv": {
                    "method": "blacklist",
                    "engine_name": "Blueliv",
                    "category": "harmless",
                    "result": "clean"
                },
                "Certego": {
                    "method": "blacklist",
                    "engine_name": "Certego",
                    "category": "harmless",
                    "result": "clean"
                },
                "Chong Lua Dao": {
                    "method": "blacklist",
                    "engine_name": "Chong Lua Dao",
                    "category": "harmless",
                    "result": "clean"
                },
                "CINS Army": {
                    "method": "blacklist",
                    "engine_name": "CINS Army",
                    "category": "malicious",
                    "result": "malicious"
                },
                "Cluster25": {
                    "method": "blacklist",
                    "engine_name": "Cluster25",
                    "category": "malicious",
                    "result": "malicious"
                },
                "CRDF": {
                    "method": "blacklist",
                    "engine_name": "CRDF",
                    "category": "malicious",
                    "result": "malicious"
                },
                "CSIS Security Group": {
                    "method": "blacklist",
                    "engine_name": "CSIS Security Group",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Snort IP sample list": {
                    "method": "blacklist",
                    "engine_name": "Snort IP sample list",
                    "category": "harmless",
                    "result": "clean"
                },
                "CMC Threat Intelligence": {
                    "method": "blacklist",
                    "engine_name": "CMC Threat Intelligence",
                    "category": "harmless",
                    "result": "clean"
                },
                "Cyan": {
                    "method": "blacklist",
                    "engine_name": "Cyan",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Cyble": {
                    "method": "blacklist",
                    "engine_name": "Cyble",
                    "category": "malicious",
                    "result": "malicious"
                },
                "CyRadar": {
                    "method": "blacklist",
                    "engine_name": "CyRadar",
                    "category": "suspicious",
                    "result": "suspicious"
                },
                "DNS8": {
                    "method": "blacklist",
                    "engine_name": "DNS8",
                    "category": "harmless",
                    "result": "clean"
                },
                "Dr.Web": {
                    "method": "blacklist",
                    "engine_name": "Dr.Web",
                    "category": "harmless",
                    "result": "clean"
                },
                "Ermes": {
                    "method": "blacklist",
                    "engine_name": "Ermes",
                    "category": "undetected",
                    "result": "unrated"
                },
                "ESET": {
                    "method": "blacklist",
                    "engine_name": "ESET",
                    "category": "harmless",
                    "result": "clean"
                },
                "ESTsecurity": {
                    "method": "blacklist",
                    "engine_name": "ESTsecurity",
                    "category": "harmless",
                    "result": "clean"
                },
                "EmergingThreats": {
                    "method": "blacklist",
                    "engine_name": "EmergingThreats",
                    "category": "harmless",
                    "result": "clean"
                },
                "Emsisoft": {
                    "method": "blacklist",
                    "engine_name": "Emsisoft",
                    "category": "harmless",
                    "result": "clean"
                },
                "Forcepoint ThreatSeeker": {
                    "method": "blacklist",
                    "engine_name": "Forcepoint ThreatSeeker",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Fortinet": {
                    "method": "blacklist",
                    "engine_name": "Fortinet",
                    "category": "malicious",
                    "result": "malware"
                },
                "G-Data": {
                    "method": "blacklist",
                    "engine_name": "G-Data",
                    "category": "harmless",
                    "result": "clean"
                },
                "GCP Abuse Intelligence": {
                    "method": "blacklist",
                    "engine_name": "GCP Abuse Intelligence",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Google Safebrowsing": {
                    "method": "blacklist",
                    "engine_name": "Google Safebrowsing",
                    "category": "harmless",
                    "result": "clean"
                },
                "GreenSnow": {
                    "method": "blacklist",
                    "engine_name": "GreenSnow",
                    "category": "malicious",
                    "result": "malicious"
                },
                "Gridinsoft": {
                    "method": "blacklist",
                    "engine_name": "Gridinsoft",
                    "category": "suspicious",
                    "result": "suspicious"
                },
                "Heimdal Security": {
                    "method": "blacklist",
                    "engine_name": "Heimdal Security",
                    "category": "harmless",
                    "result": "clean"
                },
                "Hunt.io Intelligence": {
                    "method": "blacklist",
                    "engine_name": "Hunt.io Intelligence",
                    "category": "undetected",
                    "result": "unrated"
                },
                "IPsum": {
                    "method": "blacklist",
                    "engine_name": "IPsum",
                    "category": "malicious",
                    "result": "malicious"
                },
                "Juniper Networks": {
                    "method": "blacklist",
                    "engine_name": "Juniper Networks",
                    "category": "harmless",
                    "result": "clean"
                },
                "Kaspersky": {
                    "method": "blacklist",
                    "engine_name": "Kaspersky",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Lionic": {
                    "method": "blacklist",
                    "engine_name": "Lionic",
                    "category": "harmless",
                    "result": "clean"
                },
                "Lumu": {
                    "method": "blacklist",
                    "engine_name": "Lumu",
                    "category": "undetected",
                    "result": "unrated"
                },
                "MalwarePatrol": {
                    "method": "blacklist",
                    "engine_name": "MalwarePatrol",
                    "category": "harmless",
                    "result": "clean"
                },
                "MalwareURL": {
                    "method": "blacklist",
                    "engine_name": "MalwareURL",
                    "category": "malicious",
                    "result": "malware"
                },
                "Malwared": {
                    "method": "blacklist",
                    "engine_name": "Malwared",
                    "category": "harmless",
                    "result": "clean"
                },
                "Netcraft": {
                    "method": "blacklist",
                    "engine_name": "Netcraft",
                    "category": "undetected",
                    "result": "unrated"
                },
                "OpenPhish": {
                    "method": "blacklist",
                    "engine_name": "OpenPhish",
                    "category": "harmless",
                    "result": "clean"
                },
                "Phishing Database": {
                    "method": "blacklist",
                    "engine_name": "Phishing Database",
                    "category": "harmless",
                    "result": "clean"
                },
                "PhishFort": {
                    "method": "blacklist",
                    "engine_name": "PhishFort",
                    "category": "undetected",
                    "result": "unrated"
                },
                "PhishLabs": {
                    "method": "blacklist",
                    "engine_name": "PhishLabs",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Phishtank": {
                    "method": "blacklist",
                    "engine_name": "Phishtank",
                    "category": "harmless",
                    "result": "clean"
                },
                "PREBYTES": {
                    "method": "blacklist",
                    "engine_name": "PREBYTES",
                    "category": "harmless",
                    "result": "clean"
                },
                "PrecisionSec": {
                    "method": "blacklist",
                    "engine_name": "PrecisionSec",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Quick Heal": {
                    "method": "blacklist",
                    "engine_name": "Quick Heal",
                    "category": "harmless",
                    "result": "clean"
                },
                "Quttera": {
                    "method": "blacklist",
                    "engine_name": "Quttera",
                    "category": "harmless",
                    "result": "clean"
                },
                "SafeToOpen": {
                    "method": "blacklist",
                    "engine_name": "SafeToOpen",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Sansec eComscan": {
                    "method": "blacklist",
                    "engine_name": "Sansec eComscan",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Scantitan": {
                    "method": "blacklist",
                    "engine_name": "Scantitan",
                    "category": "harmless",
                    "result": "clean"
                },
                "SCUMWARE.org": {
                    "method": "blacklist",
                    "engine_name": "SCUMWARE.org",
                    "category": "harmless",
                    "result": "clean"
                },
                "Seclookup": {
                    "method": "blacklist",
                    "engine_name": "Seclookup",
                    "category": "harmless",
                    "result": "clean"
                },
                "SecureBrain": {
                    "method": "blacklist",
                    "engine_name": "SecureBrain",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Segasec": {
                    "method": "blacklist",
                    "engine_name": "Segasec",
                    "category": "undetected",
                    "result": "unrated"
                },
                "SOCRadar": {
                    "method": "blacklist",
                    "engine_name": "SOCRadar",
                    "category": "malicious",
                    "result": "malware"
                },
                "Sophos": {
                    "method": "blacklist",
                    "engine_name": "Sophos",
                    "category": "harmless",
                    "result": "clean"
                },
                "Spam404": {
                    "method": "blacklist",
                    "engine_name": "Spam404",
                    "category": "harmless",
                    "result": "clean"
                },
                "StopForumSpam": {
                    "method": "blacklist",
                    "engine_name": "StopForumSpam",
                    "category": "harmless",
                    "result": "clean"
                },
                "Sucuri SiteCheck": {
                    "method": "blacklist",
                    "engine_name": "Sucuri SiteCheck",
                    "category": "harmless",
                    "result": "clean"
                },
                "ThreatHive": {
                    "method": "blacklist",
                    "engine_name": "ThreatHive",
                    "category": "harmless",
                    "result": "clean"
                },
                "Threatsourcing": {
                    "method": "blacklist",
                    "engine_name": "Threatsourcing",
                    "category": "harmless",
                    "result": "clean"
                },
                "Trustwave": {
                    "method": "blacklist",
                    "engine_name": "Trustwave",
                    "category": "harmless",
                    "result": "clean"
                },
                "Underworld": {
                    "method": "blacklist",
                    "engine_name": "Underworld",
                    "category": "undetected",
                    "result": "unrated"
                },
                "URLhaus": {
                    "method": "blacklist",
                    "engine_name": "URLhaus",
                    "category": "harmless",
                    "result": "clean"
                },
                "URLQuery": {
                    "method": "blacklist",
                    "engine_name": "URLQuery",
                    "category": "undetected",
                    "result": "unrated"
                },
                "Viettel Threat Intelligence": {
                    "method": "blacklist",
                    "engine_name": "Viettel Threat Intelligence",
                    "category": "harmless",
                    "result": "clean"
                },
                "VIPRE": {
                    "method": "blacklist",
                    "engine_name": "VIPRE",
                    "category": "undetected",
                    "result": "unrated"
                },
                "VX Vault": {
                    "method": "blacklist",
                    "engine_name": "VX Vault",
                    "category": "harmless",
                    "result": "clean"
                },
                "ViriBack": {
                    "method": "blacklist",
                    "engine_name": "ViriBack",
                    "category": "harmless",
                    "result": "clean"
                },
                "Webroot": {
                    "method": "blacklist",
                    "engine_name": "Webroot",
                    "category": "harmless",
                    "result": "clean"
                },
                "Yandex Safebrowsing": {
                    "method": "blacklist",
                    "engine_name": "Yandex Safebrowsing",
                    "category": "harmless",
                    "result": "clean"
                },
                "ZeroCERT": {
                    "method": "blacklist",
                    "engine_name": "ZeroCERT",
                    "category": "harmless",
                    "result": "clean"
                },
                "desenmascara.me": {
                    "method": "blacklist",
                    "engine_name": "desenmascara.me",
                    "category": "harmless",
                    "result": "clean"
                },
                "malwares.com URL checker": {
                    "method": "blacklist",
                    "engine_name": "malwares.com URL checker",
                    "category": "harmless",
                    "result": "clean"
                },
                "securolytics": {
                    "method": "blacklist",
                    "engine_name": "securolytics",
                    "category": "harmless",
                    "result": "clean"
                },
                "Xcitium Verdict Cloud": {
                    "method": "blacklist",
                    "engine_name": "Xcitium Verdict Cloud",
                    "category": "undetected",
                    "result": "unrated"
                },
                "zvelo": {
                    "method": "blacklist",
                    "engine_name": "zvelo",
                    "category": "undetected",
                    "result": "unrated"
                },
                "ZeroFox": {
                    "method": "blacklist",
                    "engine_name": "ZeroFox",
                    "category": "undetected",
                    "result": "unrated"
                }
            },
            "reputation": -15,
            "total_votes": {
                "harmless": 0,
                "malicious": 3
            },
            "country": "DE",
            "tags": [],
            "last_analysis_stats": {
                "malicious": 15,
                "suspicious": 5,
                "undetected": 27,
                "harmless": 52,
                "timeout": 0
            },
            "network": "94.159.96.0/20",
            "last_modification_date": 1740642365,
            "continent": "EU",
            "whois_date": 1739068842,
            "as_owner": "H2nexus Ltd",
            "last_analysis_date": 1739254518
        }
    }
}