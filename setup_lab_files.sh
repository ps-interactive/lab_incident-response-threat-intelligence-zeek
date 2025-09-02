#!/bin/bash
# Setup script to ensure all expected files and logs exist for the lab

# Create extract_files directory if needed
mkdir -p /home/ubuntu/zeek_analysis/extract_files
cd /home/ubuntu/zeek_analysis

# Only create files.log if it doesn't exist
if [ ! -f files.log ]; then
cat > files.log << 'FILESLOG'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files
#open	2025-08-31-14-00-00
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	duration	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff	extracted_size
#types	time	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	interval	bool	bool	count	count	count	count	bool	string	string	string	string	string	bool	count
1756652095.126649	FsiSqI1WLLlY9GyLV5	192.168.1.75	185.220.101.50	CuKFds3dfSNJC2k5Xa	HTTP	0	MD5,SHA256,EXTRACT	application/x-dosexec	-	0.100000	F	F	10240	10240	0	0	F	-	9ce3bb74469869d10b50d343edef600e	aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d	30b045a7d9e09570072999e1cdef0e00cc1add72a0db594057b19ccdba686d04	extract-1756653817.607456-HTTP-FsiSqI1WLLlY9GyLV5	F	10240
#close	2025-08-31-14-00-00
FILESLOG
fi

# Back up existing notice.log if it exists
if [ -f notice.log ]; then
    cp notice.log notice.log.backup
fi

# Create a new notice.log with BOTH file-related notices
cat > notice.log << 'NOTICELOG'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2025-08-31-14-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1756652095.140000	-	185.220.101.50	-	192.168.1.75	-	FsiSqI1WLLlY9GyLV5	application/x-dosexec	-	-	MalwareDetection::Known_Malware_Hash	Known malware detected! Hash: 9ce3bb74469869d10b50d343edef600e	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.141000	-	185.220.101.50	-	192.168.1.75	-	FsiSqI1WLLlY9GyLV5	application/x-dosexec	malware.exe	-	SuspiciousFiles::Suspicious_File_Type	Suspicious file type detected: malware.exe	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
#close	2025-08-31-14-00-00
NOTICELOG

# If there was a backup with other notices, merge them
if [ -f notice.log.backup ]; then
    # Extract non-file notices from backup
    grep -v "^#" notice.log.backup | grep -v "Suspicious_File_Type" | grep -v "Known_Malware_Hash" > /tmp/other_notices.tmp 2>/dev/null || true
    
    if [ -s /tmp/other_notices.tmp ]; then
        # Remove close tag from current notice.log
        grep -v "^#close" notice.log > /tmp/notice_with_headers.tmp
        
        # Add other notices
        cat /tmp/other_notices.tmp >> /tmp/notice_with_headers.tmp
        
        # Add close tag
        echo "#close	2025-08-31-14-00-00" >> /tmp/notice_with_headers.tmp
        
        # Replace notice.log
        mv /tmp/notice_with_headers.tmp notice.log
    fi
    
    # Clean up
    rm -f notice.log.backup /tmp/other_notices.tmp
fi

# Set proper permissions
chown -R ubuntu:ubuntu /home/ubuntu/zeek_analysis/
chmod 644 /home/ubuntu/zeek_analysis/*.log 2>/dev/null
chmod 644 /home/ubuntu/zeek_analysis/*.pcap 2>/dev/null
chmod 755 /home/ubuntu/zeek_analysis/extract_files/ 2>/dev/null
