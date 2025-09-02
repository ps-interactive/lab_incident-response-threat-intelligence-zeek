@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/ssh

module CorrelationRules;

export {
    redef enum Notice::Type += {
        SSH_Brute_Force_Attack,
        Multi_Stage_Attack,
        C2_Communication_Pattern,
        Data_Exfiltration_Suspected
    };
    
    # Thresholds
    const ssh_failure_threshold = 5 &redef;
    const ssh_failure_interval = 30sec &redef;
    const c2_beacon_count = 5 &redef;
    const c2_beacon_interval = 5min &redef;
    const exfil_threshold = 10485760 &redef;  # 10MB
    
    # Track attack stages
    global attack_stages: table[addr] of set[string] &create_expire=30min;
    global ssh_failures: table[addr] of count &create_expire=5min &default=0;
    global beacon_patterns: table[addr] of vector of time &create_expire=30min;
}

# SSH Brute Force Detection - using actual Zeek SSH events
event ssh_auth_failed(c: connection)
{
    local src = c$id$orig_h;
    ssh_failures[src] += 1;
    
    if ( ssh_failures[src] >= ssh_failure_threshold )
    {
        NOTICE([$note=SSH_Brute_Force_Attack,
                $msg=fmt("SSH brute force detected from %s after %d failures", 
                        src, ssh_failures[src]),
                $conn=c,
                $src=src]);
        
        # Add to attack stages
        if ( src !in attack_stages )
            attack_stages[src] = set();
        add attack_stages[src]["ssh_brute_force"];
    }
}

# Track successful SSH after failures
event ssh_auth_successful(c: connection, auth_method_none: bool)
{
    local src = c$id$orig_h;
    
    # Check if this follows failed attempts
    if ( src in ssh_failures && ssh_failures[src] > 0 )
    {
        NOTICE([$note=SSH_Brute_Force_Attack,
                $msg=fmt("Successful SSH login after %d failed attempts from %s",
                        ssh_failures[src], src),
                $conn=c,
                $src=src]);
        
        delete ssh_failures[src];
    }
}

# C2 Beacon Detection
event connection_established(c: connection)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    # Track connection timing for beacon detection
    if ( src !in beacon_patterns )
        beacon_patterns[src] = vector();
    
    beacon_patterns[src] += network_time();
    
    # Check for regular intervals
    if ( |beacon_patterns[src]| >= c2_beacon_count )
    {
        local regular_beacon = T;
        local prev_time = beacon_patterns[src][0];
        
        for ( i in beacon_patterns[src] )
        {
            if ( i > 0 )
            {
                local time_diff = beacon_patterns[src][i] - prev_time;
                # Simple check - if intervals vary by more than 30 seconds, not regular
                if ( time_diff > 90sec || time_diff < 30sec )
                    regular_beacon = F;
                
                prev_time = beacon_patterns[src][i];
            }
        }
        
        if ( regular_beacon )
        {
            NOTICE([$note=C2_Communication_Pattern,
                    $msg=fmt("Regular beacon pattern detected from %s to %s", src, dst),
                    $conn=c,
                    $src=src]);
            
            if ( src !in attack_stages )
                attack_stages[src] = set();
            add attack_stages[src]["c2_beacon"];
        }
    }
}

# Multi-Stage Attack Correlation
event connection_state_remove(c: connection)
{
    local src = c$id$orig_h;
    
    # Check for multi-stage attack patterns
    if ( src in attack_stages && |attack_stages[src]| >= 2 )
    {
        local stages_str = "";
        for ( stage in attack_stages[src] )
            stages_str = fmt("%s %s", stages_str, stage);
        
        NOTICE([$note=Multi_Stage_Attack,
                $msg=fmt("Multi-stage attack detected from %s: %s", src, stages_str),
                $conn=c,
                $src=src]);
    }
    
    # Data Exfiltration Detection
    if ( c$orig?$num_bytes_ip && c$orig$num_bytes_ip > exfil_threshold )
    {
        NOTICE([$note=Data_Exfiltration_Suspected,
                $msg=fmt("Large data transfer detected: %d bytes from %s to %s",
                        c$orig$num_bytes_ip, src, c$id$resp_h),
                $conn=c,
                $src=src]);
        
        if ( src !in attack_stages )
            attack_stages[src] = set();
        add attack_stages[src]["data_exfiltration"];
    }
}

# Track scan activity from detect_scans script
event Notice::log_notice(n: Notice::Info)
{
    # Check if this is a port scan notice
    if ( n$note == PortScan::Vertical_Port_Scan && n?$src )
    {
        if ( n$src !in attack_stages )
            attack_stages[n$src] = set();
        add attack_stages[n$src]["port_scan"];
    }
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    local src = c$id$orig_h;
    
    # Check for exploitation attempts
    if ( /select.*from|union.*select|\.\.\/|cmd=|exec\(/ in unescaped_URI )
    {
        if ( src !in attack_stages )
            attack_stages[src] = set();
        add attack_stages[src]["exploitation_attempt"];
        
        # Check if this follows reconnaissance
        if ( "port_scan" in attack_stages[src] )
        {
            NOTICE([$note=Multi_Stage_Attack,
                    $msg=fmt("Exploitation attempt following reconnaissance from %s", src),
                    $conn=c,
                    $src=src]);
        }
    }
}

event zeek_init()
{
    # Initialization message
    print "Correlation rules loaded - tracking multi-stage attacks";
}
