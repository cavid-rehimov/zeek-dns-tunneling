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
