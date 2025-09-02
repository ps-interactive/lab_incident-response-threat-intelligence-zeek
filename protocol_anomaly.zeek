@load base/frameworks/notice
@load base/protocols/http
@load base/protocols/dns

module ProtocolAnomaly;

export {
    redef enum Notice::Type += {
        Protocol_Mismatch,
        Missing_HTTP_Headers,
        Suspicious_DNS_Query,
        Non_Standard_Port_Usage
    };
    
    # Define standard ports for protocols
    const standard_http_ports: set[port] = { 80/tcp, 8080/tcp, 8000/tcp } &redef;
    const standard_https_ports: set[port] = { 443/tcp, 8443/tcp } &redef;
    const standard_ssh_ports: set[port] = { 22/tcp } &redef;
    
    # DNS anomaly thresholds
    const suspicious_domain_length = 50 &redef;
    const suspicious_label_length = 30 &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    # Check for HTTP on HTTPS port
    if ( c$id$resp_p in standard_https_ports && c?$service )
    {
        for ( s in c$service )
        {
            if ( s == "http" )
            {
                NOTICE([$note=Protocol_Mismatch,
                        $msg=fmt("Plain HTTP on HTTPS port %s", c$id$resp_p),
                        $conn=c]);
                break;
            }
        }
    }
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    # Check for missing Host header in HTTP/1.1
    if ( version == "1.1" && ! c$http?$host )
    {
        NOTICE([$note=Missing_HTTP_Headers,
                $msg="HTTP/1.1 request missing Host header",
                $conn=c]);
    }
    
    # Check for missing User-Agent
    if ( ! c$http?$user_agent )
    {
        NOTICE([$note=Missing_HTTP_Headers,
                $msg="HTTP request missing User-Agent header",
                $conn=c]);
    }
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    # Check for suspiciously long domain names (possible DNS tunneling)
    if ( |query| > suspicious_domain_length )
    {
        NOTICE([$note=Suspicious_DNS_Query,
                $msg=fmt("Unusually long DNS query: %d characters", |query|),
                $conn=c,
                $sub=query]);
    }
    
    # Check for suspicious label lengths
    local labels = split_string(query, /\./);
    for ( i in labels )
    {
        if ( |labels[i]| > suspicious_label_length )
        {
            NOTICE([$note=Suspicious_DNS_Query,
                    $msg=fmt("DNS label exceeds normal length: %s", labels[i]),
                    $conn=c]);
            break;
        }
    }
    
    # Check for hex-encoded domains (common in malware)
    if ( /^[0-9a-f]{32,}/ in query )
    {
        NOTICE([$note=Suspicious_DNS_Query,
                $msg="Possible hex-encoded DNS query detected",
                $conn=c,
                $sub=query]);
    }
}

event connection_state_remove(c: connection)
{
    # Check for services on non-standard ports
    if ( c?$service )
    {
        for ( s in c$service )
        {
            if ( s == "ssh" && c$id$resp_p !in standard_ssh_ports )
            {
                NOTICE([$note=Non_Standard_Port_Usage,
                        $msg=fmt("SSH service on non-standard port %s", c$id$resp_p),
                        $conn=c]);
            }
            
            if ( s == "http" && c$id$resp_p !in standard_http_ports )
            {
                NOTICE([$note=Non_Standard_Port_Usage,
                        $msg=fmt("HTTP service on non-standard port %s", c$id$resp_p),
                        $conn=c]);
            }
        }
    }
}
