@load base/frameworks/notice

module PortScan;

export {
    redef enum Notice::Type += {
        Vertical_Port_Scan,
        Horizontal_Port_Scan
    };
    
    # Track scan attempts
    global vertical_scans: table[addr] of set[port] &create_expire=5min;
    global horizontal_scans: table[port] of set[addr] &create_expire=5min;
    
    const vertical_threshold = 10 &redef;
    const horizontal_threshold = 5 &redef;
}

event connection_attempt(c: connection)
{
    # Check for failed connection attempts
    if ( c$history == "S" || c$history == "Sr" || c$conn$conn_state == "S0" )
    {
        local src = c$id$orig_h;
        local dst = c$id$resp_h;
        local dst_port = c$id$resp_p;
        
        # Track vertical scanning (one source, many ports)
        if ( src !in vertical_scans )
            vertical_scans[src] = set();
        add vertical_scans[src][dst_port];
        
        # Check for vertical scan threshold
        if ( |vertical_scans[src]| == vertical_threshold )
        {
            NOTICE([$note=Vertical_Port_Scan,
                    $msg=fmt("Vertical port scan detected from %s (scanned %d different ports)", 
                            src, |vertical_scans[src]|),
                    $src=src,
                    $identifier=cat(src, "_vertical")]);
        }
        
        # Track horizontal scanning (one port, many hosts)
        if ( dst_port !in horizontal_scans )
            horizontal_scans[dst_port] = set();
        add horizontal_scans[dst_port][dst];
        
        # Check for horizontal scan threshold
        if ( |horizontal_scans[dst_port]| == horizontal_threshold )
        {
            NOTICE([$note=Horizontal_Port_Scan,
                    $msg=fmt("Horizontal scan detected on port %s (targeted %d different hosts)", 
                            dst_port, |horizontal_scans[dst_port]|),
                    $identifier=cat(dst_port, "_horizontal")]);
        }
    }
}

# Also handle regular connection events for better detection
event connection_state_remove(c: connection)
{
    # Additional check for completed but rejected connections
    if ( c$conn$conn_state == "REJ" || c$conn$conn_state == "RSTO" )
    {
        local src = c$id$orig_h;
        local dst_port = c$id$resp_p;
        
        if ( src !in vertical_scans )
            vertical_scans[src] = set();
        add vertical_scans[src][dst_port];
        
        # Lower threshold for REJ connections as they're more suspicious
        if ( |vertical_scans[src]| >= 5 && |vertical_scans[src]| < vertical_threshold )
        {
            NOTICE([$note=Vertical_Port_Scan,
                    $msg=fmt("Likely vertical port scan from %s (multiple rejected connections)", src),
                    $src=src,
                    $conn=c,
                    $identifier=cat(src, "_vertical_rej")]);
        }
    }
}
