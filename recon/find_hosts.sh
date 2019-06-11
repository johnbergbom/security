#!/bin/bash

# Script for finding hosts of a target organization.
# Author: John Bergbom

# TODO: Make sure that this script adds to a separate file all hosts that
# were indeed discovered but that the logic decided to not add. Then we
# can later manually check that list to see if some of those hosts were
# really hosts that do belong to the target organization.

if [ $# -ne 4 ]; then
    echo "Syntax: $0 <domain> slow|fast|veryfast <directory> <workspace-name>" > /dev/stderr
    echo "directory:      where the temporary files should be stored" > /dev/stderr
    echo "workspace-name: name of the recon-ng workspace." > /dev/stderr
    exit 1
fi

domain=$1
speed=$2
dir=$3
workspace=$4

if [[ "$speed" != "slow" ]] && [[ "$speed" != "fast" ]] && [[ "$speed" != "veryfast" ]]; then
    echo "Syntax: $0 <domain> slow|fast|veryfast"
    exit 1
fi

if ! host $domain > /dev/null; then
    echo "Couldn't resolve $domain"
    exit 1
fi

#dir=$(mktemp -d)
#workspace=$(echo $(date) $dir | md5sum | sed 's/ .*$//')
#dir="/tmp/tmp.fIlVdoWjUi"
#workspace="4869283fe9acd65828d96e19ad27a68f"
#dir="/tmp/tmp.yqie36TszG"
#workspace="fca9b9876423a34df699e4399ccdd22b"

if [ ! -d "$dir" ]; then
    mkdir "$dir"
fi
echo "Using the recon-ng workspace $workspace" | tee -a "$dir"/run.log
echo "Working directory: $dir" | tee -a "$dir"/run.log


# The command parameter can consist of several commands like this:
# "use reverse_resolve\nset subnet 192.89.38.0/24"
#function run_command(msg,command,verbose) {
function run_command {
    msg=$1
    command=$2
    verbose=$3
    if [ "$msg" != "" ]; then
        echo "$msg"
    fi
    cd /usr/local/recon-ng
    if [ "$verbose" == "true" ]; then
	./recon-ng -w "$workspace" --no-check <<-EOF | tee -a "$dir"/run.log
        $(echo -e "$command")
        run
        exit
        exit
EOF
    else
	./recon-ng -w "$workspace" --no-check <<-EOF >> "$dir"/run.log
        $(echo -e "$command")
        run
        exit
        exit
EOF
    fi
    cd - > /dev/null
}


function extract_found_domains {
    # Extract the domains that exist. For example www.site.com and dev.site.com
    # correspond to the domain site.com.
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select host from hosts where host is not null;" \
	| grep -v -E '^((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])$' \
	| awk -F. '{ print $(NF-1) "." $NF }' | sort | uniq > "$dir"/found_domains.txt
    if [ ! -s "$dir"/found_domains.txt ]; then
	echo "$domain" | awk -F. '{ print $(NF-1) "." $NF }' > "$dir"/found_domains.txt
    fi
}

function simple_host_searches {
    extract_found_domains
    cat "$dir"/found_domains.txt \
    | while read -r domain_to_try; do
	if ! grep -q "^${domain_to_try}$" "$dir"/function_simple_host_searches.done; then
	    echo "Simple host searches for $domain_to_try..."
	    run_command "" "set domain $domain_to_try" false

	    #run_command "  Searching hosts with netcraft..." "use netcraft" false
	    run_command "  Searching hosts with netcraft..." "use recon/hosts/gather/http/web/netcraft" false
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'netcraft' where host is not null and source is null;" 2> /dev/null
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select source, host, ip_address from hosts where source = 'netcraft' order by host;" \
		>> "$dir"/host_sources.txt
	    run_command "  Searching hosts with shodan_hostname..." "use shodan_hostname" false
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'shodan_hostname' where host is not null and source is null;" \
		2> /dev/null
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select source, host, ip_address from hosts where source = 'shodan_hostname' order by host;" \
		>> "$dir"/host_sources.txt
	    run_command "  Searching hosts with baidu_site..." "use baidu_site" false
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'baidu_site' where host is not null and source is null;" \
		2> /dev/null
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select source, host, ip_address from hosts where source = 'baidu_site' order by host;" \
		>> "$dir"/host_sources.txt
	    run_command "  Searching hosts with bing_domain..." "use bing_domain" false
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'bing_domain' where host is not null and source is null;" \
		2> /dev/null
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select source, host, ip_address from hosts where source = 'bing_domain' order by host;" \
		>> "$dir"/host_sources.txt
	    run_command "  Searching hosts with yahoo_site..." "use yahoo_site" false
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'yahoo_site' where host is not null and source is null;" \
		2> /dev/null
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select source, host, ip_address from hosts where source = 'yahoo_site' order by host;" \
		>> "$dir"/host_sources.txt
            #run_command "  Searching hosts with brute_force..." "use brute_force" false
            #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
	    #    "update hosts set source = 'brute_force' where host is not null and source is null;" \
	    #    2> /dev/null
            #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
	    #    "select source, host, ip_address from hosts where source = 'brute_force' order by host;" \
	    #    >> "$dir"/host_sources.txt
	    run_command "  Searching hosts with api/google_site..." "use api/google_site" false
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'api/google_site' where host is not null and source is null;" \
		2> /dev/null
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select source, host, ip_address from hosts where source = 'api/google_site' order by host;" \
		>> "$dir"/host_sources.txt
	    run_command "  Searching hosts with web/google_site..." "use web/google_site" false
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'web/google_site' where host is not null and source is null;" \
		2> /dev/null
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select source, host, ip_address from hosts where source = 'web/google_site' order by host;" \
		>> "$dir"/host_sources.txt
	    #run_command "  Found the following hosts so far:" "query select * from hosts order by host;" true
	    echo "$domain_to_try" >> "$dir"/function_simple_host_searches.done
	fi
    done
    run_command "" "set domain $domain" false
    rm "$dir"/found_domains.txt
}

# We need to compare the ip-address to the range number by number
# using arithmetic comparison.
function ip_within_range {
    ip_to_check=$1
    range_start=$2
    range_end=$3
    i1=$(echo $ip_to_check | cut -d'.' -f1)
    i2=$(echo $ip_to_check | cut -d'.' -f2)
    i3=$(echo $ip_to_check | cut -d'.' -f3)
    i4=$(echo $ip_to_check | cut -d'.' -f4)
    s1=$(echo $range_start | cut -d'.' -f1)
    s2=$(echo $range_start | cut -d'.' -f2)
    s3=$(echo $range_start | cut -d'.' -f3)
    s4=$(echo $range_start | cut -d'.' -f4)
    e1=$(echo $range_end | cut -d'.' -f1)
    e2=$(echo $range_end | cut -d'.' -f2)
    e3=$(echo $range_end | cut -d'.' -f3)
    e4=$(echo $range_end | cut -d'.' -f4)
    if [[ $i1 -ge $s1 ]] && [[ $i2 -ge $s2 ]] && [[ $i3 -ge $s3 ]] && [[ $i4 -ge $s4 ]]; then
	if [[ $i1 -le $e1 ]] && [[ $i2 -le $e2 ]] && [[ $i3 -le $e3 ]] && [[ $i4 -le $e4 ]]; then
	    return 0
	fi
    fi
    return 1
}

function extract_host_middle_names {
    # Extract "middle" parts of hostnames that exist in the database.
    # For example if www.site.com exists in the database, then its
    # middle part is "site".
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select host from hosts where host is not null;" \
	| grep -v -E '^((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])$' \
	| awk -F. '{ print $(NF-1) }' | sort | uniq > "$dir"/hostname_middle_parts.txt
    if [ ! -s "$dir"/hostname_middle_parts.txt ]; then
	echo "$domain" | awk -F. '{ print $(NF-1) }' > "$dir"/hostname_middle_parts.txt
    fi
}

# Check if this ip-address belongs to an ip-range of the organization.
#function ip_belongs_to_org(ip_to_check) {
function ip_belongs_to_org {
    ip_belongs_to=$1
    belongs_to_ret_val=1
    extract_host_middle_names
    for middle_name in $(cat "$dir"/hostname_middle_parts.txt); do
	for range_start in $(grep -i $middle_name "$dir"/netrange_list.txt | cut -d' ' -f1); do
	    range=$(grep $range_start "$dir"/whois_cidr_list.txt)
	    hostmin=$(ipcalc -n "$range" | grep -E "^Address:"|sed 's/ \+/ /'|cut -d' ' -f2)
	    hostmax=$(ipcalc -n "$range" | grep -E "^Broadcast:"|sed 's/ \+/ /'|cut -d' ' -f2)
	    #echo "ip: $ip, hostmin: $hostmin, hostmax: $hostmax"
	    if ip_within_range $ip_belongs_to $hostmin $hostmax; then
		belongs_to_ret_val=0
		break
	    fi
	done
    done
    rm "$dir"/hostname_middle_parts.txt
    return $belongs_to_ret_val;
}

# Checks if the given name_to_test matches a "middle" name
# that already exists in the database.
#function name_matches_existing_middle_name(name_to_test) {
function name_matches_existing_middle_name {
    name_to_test=$1
    matches=1;
    extract_host_middle_names
    middle_name=$(echo $name_to_test | awk -F. '{ print $(NF-1) }')
    if grep -q "^${middle_name}$" "$dir"/hostname_middle_parts.txt; then
	matches=0
    fi
    rm "$dir"/hostname_middle_parts.txt
    return $matches;
}

#function nmap_subnet_scan(subnet_param) {
function nmap_subnet_scan {
    subnet_param=$1

    # Portscan such subnets that are owned by the organization.
    name=$(echo $domain | sed 's/\..*$//')
    for var in $(echo $subnet_param); do
	if ! grep -q "^${var}$" "$dir"/function_nmap_subnet_scan.done; then
	    # Only nmap such subnets that are owned by the organization.
	    grep $(echo "$var" | sed 's/\/.*$//') "$dir"/netrange_list.txt | grep -i -q "$name"
	    owns_subnet=$?
	    if [ $owns_subnet -eq 0 ]; then
		echo "Portscanning the following subnet with nmap: $var" | tee -a "$dir"/run.log
	        #nmap -oG - -T5 $subnets | tee -a "$dir"/run.log | tee "$dir"/nmap_scan.log
		nmap -oG - -T5 $var | tee -a "$dir"/run.log >> "$dir"/nmap_scan.log
	    else
		echo "Skipping portscan of subnet $var because it's not owned by the organization" \
		    | tee -a "$dir"/run.log
	    fi
	    echo "$var" >> "$dir"/function_nmap_subnet_scan.done
	fi
    done

    # Additionally we should nmap all hosts in the hosts table
    # even if they don't belong to the customer's subnet.
    # Reason: we want to know which ports are open.
    echo "Portscanning the hosts found so far." | tee -a "$dir"/run.log
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
	"select ip_address from hosts where ip_address is not null order by ip_address;" \
	| uniq \
	| while read -r ip; do
	if ! ipcalc -n "$ip" | grep -q "Private Internet"; then # skip private addresses
	    if ! grep -q "^${ip}$" "$dir"/function_nmap_subnet_scan.done; then
		nmap -oG - -T5 $ip | tee -a "$dir"/run.log >> "$dir"/nmap_scan.log
		echo "$ip" >> "$dir"/function_nmap_subnet_scan.done
	    fi
	fi
    done

    cat "$dir"/nmap_scan.log | grep "Status: Up"|sed 's/[\t]*Status: Up$//'|sed 's/Host: //' \
    | while read -r ip hostname; do
	# Check if this ip-address belongs to an ip-range of the organization
	belongs_to_org=0
	if ip_belongs_to_org "$ip"; then
	    #echo "$ip belongs to org ($hostname)"
	    belongs_to_org=1
	#else
	    #echo "$ip does NOT belong to org ($hostname)"
	fi

	fixed_hostname=$(echo $hostname | sed 's/[()]//g')
	if [ "$fixed_hostname" != "" ]; then
	    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where host = \"$fixed_hostname\" and ip_address = \"$ip\";")
	    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		# For hosts not belonging to an ip-range of the organization
		# the host should be added if it matches an existing "middle"
		# name.
		add=1;
		if [ $belongs_to_org -eq 0 ]; then
		    add=0
		    if name_matches_existing_middle_name "$fixed_hostname"; then
			#echo "$fixed_hostname matches existing middle name, adding"
			add=1
		    #else
			#echo "$fixed_hostname does NOT match existing middle name, not adding"
		    fi
		fi

		if [ $add -eq 1 ]; then
		    echo "Nmap found new host: $ip $fixed_hostname" | tee -a "$dir"/run.log
		    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (host,ip_address,source) values (\"$fixed_hostname\",\"$ip\",\"nmap\");"
		    echo "nmap|$fixed_hostname|$ip" >> "$dir"/host_sources.txt
		fi
            fi
	else
	    #exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where ip_address = \"$ip\" and (host = '' or host is null);")
	    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where ip_address = \"$ip\";")
	    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		# Only add the ip-address if it belongs to the organization
		if [ $belongs_to_org -eq 1 ]; then
		    echo "Nmap found new host: $ip" | tee -a "$dir"/run.log
		    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (ip_address,source) values (\"$ip\",\"nmap\");"
		    echo "nmap||$ip" >> "$dir"/host_sources.txt
		fi
            fi
	fi
    done
    #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select source, host, ip_address from hosts where source = 'nmap' order by host;" >> "$dir"/host_sources.txt
}

# Brute force DNS using fierce
function dns_brute_force {
    extract_found_domains
    cat "$dir"/found_domains.txt \
    | while read -r; do
	if ! grep -q "^${REPLY}$" "$dir"/function_dns_brute_force.done; then
	    do_brute_force=1
            #./fierce.pl -dns "$domain" | tee "$dir"/fierce_output_${REPLY}.log
	    if [ "$speed" == "veryfast" ]; then
		echo "Skipping bruteforcing of DNS for domain $REPLY..." | tee -a "$dir"/run.log
		do_brute_force=0
	    elif [ "$speed" == "fast" ]; then
		echo "Bruteforcing DNS for domain $REPLY..." | tee -a "$dir"/run.log
		./fierce.pl -dns "$REPLY" > "$dir"/fierce_output_${REPLY}.log
	    else
		echo "Bruteforcing DNS for domain $REPLY..." | tee -a "$dir"/run.log
		name=$(echo $REPLY | sed 's/\..*$//')
		# Note: here we could possibly set the -search parameter
		# to all the middle names found so far.
		./fierce.pl -dns "$REPLY" -search $name -wide > "$dir"/fierce_output_${REPLY}.log
	    fi
	    if [ $do_brute_force -eq 1 ]; then
		grep -A 10000 "^DNS Servers for" "$dir"/fierce_output_${REPLY}.log \
		    | grep -B 10000 "Trying zone transfer first" \
		    | grep -E -v "DNS Servers for|Trying zone transfer first" | grep -v ^$ | sed 's/^[ \t]*//' \
		    > "$dir"/dns_servers_${REPLY}.txt
		grep ^[0-9] "$dir"/fierce_output_${REPLY}.log > "$dir"/fierce_found_hosts_${REPLY}.txt
    
                # All dns servers are not always included, so add them if necessary,
		# but if they don't belong to a subnet for the organization, then only
		# add if the name matches.
		cat "$dir"/dns_servers_${REPLY}.txt \
		    | while read -r dns_server; do
		    if ! grep -q "$dns_server" "$dir"/fierce_found_hosts_${REPLY}.txt; then
			dns_server_ip=$(host $dns_server)
			if [ $? -eq 0 ]; then
			    belongs_to_org=0
			    if ip_belongs_to_org "$(echo $dns_server_ip | sed 's/^.* //')"; then
				belongs_to_org=1
			    fi

			    add=1;
			    if [ $belongs_to_org -eq 0 ]; then
				add=0
				if name_matches_existing_middle_name "$dns_server"; then
				    add=1
				fi
			    fi
			    
			    if [ $add -eq 1 ]; then
		                #echo "Adding DNS server $dns_server"
				echo -e "$(echo $dns_server_ip | sed 's/^.* //')\t${dns_server}" \
				    >> "$dir"/fierce_found_hosts_${REPLY}.txt
			    fi
			fi
		    fi
		done

                # Enter the new hosts the fierce found into the database
                #"grep ^[0-9] "$dir"/fierce_output_${REPLY}.log | while read -r ip hostname; do
		cat "$dir"/fierce_found_hosts_${REPLY}.txt | while read -r ip hostname; do
		    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
			"select count(*) from hosts where host = \"$hostname\" and ip_address = \"$ip\";")
		    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
			echo "Fierce found new host: $ip $hostname" | tee -a "$dir"/run.log
			sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
			    "insert into hosts (host,ip_address,source) values (\"$hostname\",\"$ip\",\"fierce\");"
			echo "fierce|$hostname|$ip" >> "$dir"/host_sources.txt
		    fi
		done
		#sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select source, host, ip_address from hosts where source = 'fierce' order by host;" >> "$dir"/host_sources.txt
	    
                #grep -A 10000 "Subnets found" "$dir"/fierce_output_${REPLY}.log \
		    #| grep -B 10000 "Done with Fierce scan" \
	            #| grep -E -v "Subnets found|Done with Fierce scan|^$" \
		    #| sed 's/^[ \t]*//g' | awk '{ print $1 }' > "$dir"/fierce_subnets.txt
		echo "$REPLY" >> "$dir"/function_dns_brute_force.done
	    fi
	fi
    done
    rm "$dir"/found_domains.txt
    cat "$dir"/dns_servers_*.txt > "$dir"/dns_servers.txt
    return
}

function find_whois_netranges {
    netrange_list=$(mktemp)
    cidr_list=$(mktemp)
    ip_addresses=$(mktemp)
    temp_file=$(mktemp)
    #echo $netrange_list
    #echo $cidr_list
    #echo $ip_addresses
    echo "Finding out netranges of hosts found so far using whois..." | tee -a "$dir"/run.log
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select ip_address from hosts where ip_address is not null order by ip_address;" | uniq > "$ip_addresses"
    cat "$ip_addresses" | while read -r; do
	if ! grep -q "^${REPLY}$" "$dir"/function_find_whois_netranges.done; then
            #echo "Looking up ip-range for ip $REPLY"
	    #if echo "$REPLY" | grep -q -E "^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\."; then
	    #    echo "Ip $REPLY is a private ip address"
	    #    echo "$REPLY" >> "$dir"/function_find_whois_netranges.done
	    #else
	        whois "$REPLY" | grep -E "^NetRange:|^CIDR:|^NetName:|^inetnum:|^netname:|^OrgName:|^CustName:|^descr:" > "$temp_file"
		if [ $? -eq 0 ]; then
		    if grep -q -E "^inetnum" "$temp_file"; then
			netrange=$(grep -E "^inetnum:" "$temp_file" | sed 's/^[^ ]\+ \+//')
			netname=$(grep -E "^netname:" "$temp_file" | sed 's/^[^ ]\+ \+//')
			descr=$(grep -E "^descr:" "$temp_file" | head -1 | sed 's/^[^ ]\+ \+//')
			cidr=$(ipcalc -r $netrange | grep -v deaggregate)
		    else
			netrange=$(grep -E "^NetRange:" "$temp_file" | tail -1 | sed 's/^[^ ]\+ \+//')
			netname=$(grep -E "^NetName:" "$temp_file" | tail -1 | sed 's/^[^ ]\+ \+//')
			cidr=$(grep -E "^CIDR:" "$temp_file" | tail -1 | sed 's/^[^ ]\+ \+//')
			org_name=$(grep -E "^OrgName:" "$temp_file" | tail -1 | sed 's/^[^ ]\+ \+//')
			if grep -q -E "^CustName:" "$temp_file"; then
			    cust_name=$(grep -E "^CustName:" "$temp_file" | head -1 | sed 's/^[^ ]\+ \+//')
			    org_name=
			fi
			descr="$org_name $cust_name"
		    fi
		    echo "Netrange for ip $REPLY: $netrange, cidr: $cidr, descr: $netname $descr" >> "$dir"/run.log
		    echo "$netrange $netname $descr" >> "$netrange_list"
		    echo "$cidr" >> "$cidr_list"
		    echo "$REPLY" >> "$dir"/function_find_whois_netranges.done
		else
		    echo "Lookup failed for $REPLY" >> "$dir"/run.log
		fi
	    #fi
	fi
    done
    # Add new netranges to any existing list
    cat "$cidr_list" | sort | uniq >> "$dir"/whois_cidr_list.txt
    cat "$netrange_list" | sort | uniq >> "$dir"/netrange_list.txt
    cat "$dir"/whois_cidr_list.txt | sort | uniq > "$cidr_list"
    cat "$dir"/netrange_list.txt | sort | uniq > "$netrange_list"
    cat "$cidr_list" > "$dir"/whois_cidr_list.txt
    cat "$netrange_list" > "$dir"/netrange_list.txt
    rm "$cidr_list" "$netrange_list" "$temp_file" "$ip_addresses"

    #echo "Found netranges:"
    #cat "$dir"/netrange_list.txt
    #echo
    #echo "Found cidr's:"
    #cat "$dir"/whois_cidr_list.txt
    #echo
    #echo
}

#function shodan_subnet_search(subnet_param) {
function shodan_subnet_search {
    subnet_param=$1
    echo "Making subnet host searches at shodan..." | tee -a "$dir"/run.log
    for subnet in $(echo "$subnet_param"); do
	if ! grep -q "^${subnet}$" "$dir"/function_shodan_subnet_search.done; then
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'dummy';" 2> /dev/null
	    run_command "" "use shodan_net\nset subnet $subnet" false
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'shodan_net' where source is null;" 2> /dev/null
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select source, host, ip_address from hosts where source = 'shodan_net' order by host;" \
		>> "$dir"/host_sources.txt
	    echo "$subnet" >> "$dir"/function_shodan_subnet_search.done
	fi
    done
}

function reverse_ip_lookups {
    # Do reverse ip lookups for all found subnets that haven't yet been done.
    # Don't yet add the found hosts to the database in this loop.
    cat "$dir"/whois_cidr_list.txt | grep -v -E "172.16.0.0/12|192.168.0.0/16|10.0.0.0/8" | \
    while read -r; do
	if ! grep -q "^${REPLY}$" "$dir"/function_reverse_ip_lookups.done; then
            # Add to the database only such hostnames that match the domain
	    # name with the top domain stripped off:
            #run_command "Make reverse ip lookups of the found subnet $REPLY..." \
	    #    "use reverse_resolve\nset regex $name\nset subnet $REPLY" false

	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'dummy';" 2> /dev/null
	    run_command "Make reverse ip lookups of the found subnet $REPLY..." \
		"use reverse_resolve\nset regex \"\"\nset subnet $REPLY" false
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"update hosts set source = 'reverse ip lookup for $REPLY' where source is null;" \
		2> /dev/null
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select host, ip_address from hosts where source like 'reverse ip lookup for%';" \
		> "$dir"/function_reverse_ip_lookups.subnet_"$(echo $REPLY | sed 's/\//_/')"
	    # Then remove the found hosts from the database (they will
	    # be added again by different logic below).
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "delete from hosts where source like 'reverse ip lookup for%';" 2> /dev/null
	    echo "$REPLY" >> "$dir"/function_reverse_ip_lookups.done
	#else
	#    echo "Reverse ip lookup already done for the subnet $REPLY"
	fi
    done

    # Now add the found hosts to the database based on the following logic:
    # 1.) If the target organization owns the subnet, then store all the found hosts.
    # 2.) If the target organization doesn't own the subnet, then only store such
    # hosts whose "middle" names match some host which already exists in the
    # database. For example if www.site.com exists in the database and then dev.site.com
    # was found in a subnet not owned by the organization, then that host should be
    # included. However site www.abc.com will not be included.
    # => The reason for this logic is that otherwise we'll get a lot of false positives
    # if the target organization doesn't own the subnet.
    echo "Adding new hosts found with reverse ip lookup to the database"

    # Add hosts belonging to subnets owned by the organization
    cat "$dir"/whois_cidr_list.txt | grep -v -E "172.16.0.0/12|192.168.0.0/16|10.0.0.0/8" | \
    while read -r; do
	# Skip subnets not belonging to the organization
	if ! ip_belongs_to_org "$(echo "$REPLY" | sed 's/\/.*$//')"; then
	    continue
	fi

	cat "$dir"/function_reverse_ip_lookups.subnet_"$(echo $REPLY | sed 's/\//_/')" | \
	while read -r line; do
	    #echo "LINE: $line"
	    hostname=$(echo $line | cut -d'|' -f1)
	    ip=$(echo $line | cut -d'|' -f2)
	    if [[ ! -z $hostname ]] && [[ ! -z $ip ]]; then
		exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    "select count(*) from hosts where host = \"$hostname\" and ip_address = \"$ip\";")
		if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		    echo "New host found with reverse ip lookup: $ip, $hostname" \
			| tee -a "$dir"/run.log
		    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
			"insert into hosts (host,ip_address,source) values (\"$hostname\",\"$ip\",\"reverse ip lookup for $REPLY\");"
		    echo "reverse ip lookup for $REPLY|$hostname|$ip" \
			>> "$dir"/host_sources.txt
		fi
	    fi
	done
    done

    # Add hosts that do not belong to subnets owned by the organization
    # if their middle name matches a known middle name.
    cat "$dir"/whois_cidr_list.txt | grep -v -E "172.16.0.0/12|192.168.0.0/16|10.0.0.0/8" | \
    while read -r; do
	# Skip subnets belonging to the organization
	if ip_belongs_to_org "$(echo "$REPLY" | sed 's/\/.*$//')"; then
	    continue
	fi

	extract_host_middle_names
	grep_string=$(cat "$dir"/hostname_middle_parts.txt | tr '\n' '|' | sed 's/|$//')
	rm "$dir"/hostname_middle_parts.txt
	cat "$dir"/function_reverse_ip_lookups.subnet_"$(echo $REPLY | sed 's/\//_/')" \
	| grep -E "$grep_string" | \
	while read -r line; do
	    #echo "LINE: $line"
	    hostname=$(echo $line | cut -d'|' -f1)
	    ip=$(echo $line | cut -d'|' -f2)
	    if [[ ! -z $hostname ]] && [[ ! -z $ip ]]; then
		add=0
		if name_matches_existing_middle_name "$hostname"; then
		    add=1
		fi

		if [ $add -eq 1 ]; then
		    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
			"select count(*) from hosts where host = \"$hostname\" and ip_address = \"$ip\";")
		    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
			echo "New host found with reverse ip lookup: $ip, $hostname" \
			    | tee -a "$dir"/run.log
			sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
			    "insert into hosts (host,ip_address,source) values (\"$hostname\",\"$ip\",\"reverse ip lookup for $REPLY\");"
			echo "reverse ip lookup for $REPLY|$hostname|$ip" \
			    >> "$dir"/host_sources.txt
		    fi
		fi
	    fi
	done
    done
}

function my_ip_neighbors {
    # For the ip_neighbor plugin we might get timeouts and in addition if it bails
    # out before all hosts are gone through, then the found servers might not be
    # stored into the database. Instead we'll make the queries manually against
    # My-IP-Neighbors.com.
    #run_command "Check for virtual hosts on the same servers..." "use ip_neighbor\nset regex \"\"" true

    entries=$(mktemp)
    temp_file=$(mktemp)
    found_hosts=$(mktemp)
    echo "Check for virtual hosts on the same servers using www.my-ip-neighbors.com..." | tee -a "$dir"/run.log

    # First query using ip addresses
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select ip_address from hosts where ip_address is not null order by ip_address;" | uniq > "$entries"
    #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select ip_address from hosts where ip_address is not null order by ip_address desc limit 20" | uniq > "$entries"
    cat "$entries" | while read -r; do
	if ! grep -q "^${REPLY}$" "$dir"/function_my_ip_neighbors.done; then
	    belongs_to_org=0
	    if ip_belongs_to_org "$REPLY"; then
		#echo "$REPLY belongs to org"
		belongs_to_org=1
	    #else
		#echo "$REPLY does NOT belong to org"
	    fi

	    echo "Getting info for $REPLY from my-ip-neighbors.com" >> "$dir"/run.log
	    wget -O "$temp_file" -o /dev/null "http://www.my-ip-neighbors.com/?domain=$REPLY"
	    if grep -q "Are you trying to kill my server" "$temp_file"; then
		echo "WARNING: maximum query limit per day was reached at my-ip-neighbors.com, aborting." | tee -a "$dir"/run.log
		break
	    fi
	    grep "whois.domaintools.com" "$temp_file" | sed 's/^.*whois.domaintools.com//' | sed 's/".*$//' | sed 's/^\///' > "$found_hosts"
	    for var in $(cat "$found_hosts"); do
	        #echo "for $REPLY we got $var"
		exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where host = \"$var\" and ip_address = \"$REPLY\";")
		if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		    # For hosts not belonging to an ip-range of the organization
		    # the host should be added if it matches an existing "middle"
		    # name.
		    add=1;
		    if [ $belongs_to_org -eq 0 ]; then
			add=0
			if name_matches_existing_middle_name "$var"; then
			    #echo "$var matches existing middle name, adding"
			    add=1
			#else
			    #echo "$var does NOT match existing middle name, not adding"
			fi
		    fi

		    if [ $add -eq 1 ]; then
			echo "My-IP-Neighbors.com found new virtual host: $var ($REPLY)" | tee -a "$dir"/run.log
			sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (host,ip_address,source) values (\"$var\",\"$REPLY\",\"My-IP-Neighbors.com\");"
			echo "My-IP-Neighbors.com|$var|$REPLY" >> "$dir"/host_sources.txt
		    fi
		fi
	    done
	    echo "$REPLY" >> "$dir"/function_my_ip_neighbors.done
	fi
    done

    # Then query for domain names for entries that have no ip-address
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select host from hosts where host is not null and ip_address is null order by host;" | uniq > "$entries"
    cat "$entries" | while read -r; do
	if ! grep -q "^${REPLY}$" "$dir"/function_my_ip_neighbors.done; then
	    echo "Getting info for $REPLY from my-ip-neighbors.com" >> "$dir"/run.log
	    wget -O "$temp_file" -o /dev/null "http://www.my-ip-neighbors.com/?domain=$REPLY"
	    if grep -q "Are you trying to kill my server" "$temp_file"; then
		echo "WARNING: maximum query limit per day was reached at my-ip-neighbors.com, aborting." | tee -a "$dir"/run.log
		break
	    fi
	    grep "whois.domaintools.com" "$temp_file" | sed 's/^.*whois.domaintools.com//' | sed 's/".*$//' | sed 's/^\///' > "$found_hosts"
	    for var in $(cat "$found_hosts"); do
		exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where host = \"$var\";")
		if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		    # Add this one either if the name matches an existing middle
		    # name or if the ip address resolves to an address that
		    # belongs to the organization.
		    add=0
		    if name_matches_existing_middle_name "$var"; then
			#echo "$var matches existing middle name, adding"
			add=1
		    else
			host "$var" > "$temp_file"
			if [ $? -eq 0 ]; then
			    for ip in $(grep "has address" "$temp_file" | sed 's/^.* //'); do
				if ip_belongs_to_org "$ip"; then
				    #echo "$var belongs to org (ip: $ip)"
				    add=1
				    break
				fi
			    done
			    #if [ $add -eq 0 ]; then
				#echo "$var does NOT belong to org"
			    #fi
			fi
		    fi

		    if [ $add -eq 1 ]; then
			echo "My-IP-Neighbors.com found new virtual host: $var" | tee -a "$dir"/run.log
			sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (host,source) values (\"$var\",\"My-IP-Neighbors.com\");"
			echo "My-IP-Neighbors.com|$var|" >> "$dir"/host_sources.txt
		    fi
		fi
	    done
	    echo "$REPLY" >> "$dir"/function_my_ip_neighbors.done
	fi
    done
    rm "$found_hosts"
    rm "$temp_file"
    rm "$entries"
    #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select source, host, ip_address from hosts where source = 'My-IP-Neighbors.com' order by host;" >> "$dir"/host_sources.txt
}

function bing_ip_search {
    #run_command "" "use bing_ip\nset regex \"\"\nset source query select ip_address from hosts where ip_address is not null order by ip_address limit 10 offset 0;" false
    #run_command "" "use bing_ip\nset regex \"\"" false
    # http://www.bing.com/search?q=ip%3A164.215.36.91&qs=n&form=QBLH&pq=ip%3A164.215.36.91&sc=0-0&sp=-1&sk=

    echo "Check for virtual hosts on the same servers using bing ip search..." | tee -a "$dir"/run.log

    # Often the bing_ip module fails. In order to increase the chance of
    # actually testing all hosts, let's test them one by one.
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select ip_address from hosts where ip_address\
    is not null order by ip_address;" | uniq \
    | while read -r ip; do
	if ! grep -q "^${ip}$" "$dir"/function_bing_ip_search.done; then
	    if ! ipcalc -n "$ip" | grep -q "Private Internet"; then # skip private addresses
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = 'dummy';" \
		    2> /dev/null
		run_command "" "use bing_ip\nset regex \"\"\nset source $ip" false
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    "update hosts set source = 'bing_ip' where source is null;" 2> /dev/null
		if ip_belongs_to_org "$ip"; then
		    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
			"select host, ip_address from hosts where source = 'bing_ip';" \
			>> "$dir"/function_bing_ip_search.found_hosts_in_org
		else
		    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
			"select host, ip_address from hosts where source = 'bing_ip';" \
			>> "$dir"/function_bing_ip_search.found_hosts_not_in_org
		fi
	        # Then remove the found hosts from the database (they will
	        # be added again by different logic below).
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    "delete from hosts where source = 'bing_ip';" 2> /dev/null
	        #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    #"select source, host, ip_address from hosts where source = 'bing_ip' order by host;" \
		    #>> "$dir"/host_sources.txt
	    fi
	    echo "$ip" >> "$dir"/function_bing_ip_search.done
	fi
    done

    # Now add the found hosts to the database based on the following logic (same
    # as for reverse_ip_lookups):
    # 1.) If the target organization owns the subnet, then store all the found hosts.
    # 2.) If the target organization doesn't own the subnet, then only store such
    # hosts whose "middle" names match some host which already exists in the
    # database. For example if www.site.com exists in the database and then dev.site.com
    # was found in a subnet not owned by the organization, then that host should be
    # included. However site www.abc.com will not be included.
    # => The reason for this logic is that otherwise we'll get a lot of false positives
    # if the target organization doesn't own the subnet.
    echo "Adding new hosts found with bing ip search to the database"

    # Add hosts belonging to subnets owned by the organization
    cat "$dir"/function_bing_ip_search.found_hosts_in_org | \
    while read -r line; do
	#echo "LINE: $line"
	hostname=$(echo $line | cut -d'|' -f1)
	ip=$(echo $line | cut -d'|' -f2)
	if [[ ! -z $hostname ]] && [[ ! -z $ip ]]; then
	    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select count(*) from hosts where host = \"$hostname\" and ip_address = \"$ip\";")
	    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		echo "New host found with bing ip search: $ip, $hostname" \
		    | tee -a "$dir"/run.log
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    "insert into hosts (host,ip_address,source) values (\"$hostname\",\"$ip\",\"bing_ip\");"
		echo "bing_ip|$hostname|$ip" \
		    >> "$dir"/host_sources.txt
	    fi
	fi
    done

    # Add hosts that do not belong to subnets owned by the organization
    # if their middle name matches a known middle name.
    extract_host_middle_names
    grep_string=$(cat "$dir"/hostname_middle_parts.txt | tr '\n' '|' | sed 's/|$//')
    rm "$dir"/hostname_middle_parts.txt
    cat "$dir"/function_bing_ip_search.found_hosts_not_in_org \
    | grep -E "$grep_string" | \
    while read -r line; do
	#echo "LINE: $line"
	hostname=$(echo $line | cut -d'|' -f1)
	ip=$(echo $line | cut -d'|' -f2)
	if [[ ! -z $hostname ]] && [[ ! -z $ip ]]; then
	    add=0
	    if name_matches_existing_middle_name "$hostname"; then
		add=1
	    fi
	    
	    if [ $add -eq 1 ]; then
		exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    "select count(*) from hosts where host = \"$hostname\" and ip_address = \"$ip\";")
		if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		    echo "New host found with bing ip search: $ip, $hostname" \
			| tee -a "$dir"/run.log
		    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
			"insert into hosts (host,ip_address,source) values (\"$hostname\",\"$ip\",\"bing_ip\");"
		    echo "bing_ip|$hostname|$ip" \
			>> "$dir"/host_sources.txt
		fi
	    fi
	fi
    done
}

function find_virtual_hosts_on_same_ip {
    my_ip_neighbors
    bing_ip_search
}

function geolocate_hosts {
    run_command "Geolocate hosts using uniapple..." "use uniapple" false
    run_command "Geolocate hosts using hostip..." "use hostip" false
    run_command "Geolocate hosts using ipinfodb..." "use ipinfodb" false
}

# Some hosts have multiple ip addresses. The dns/resolve-module of recon-ng only tries to resolve
# such hostnames that have no ip addresses at all. This method, however, tries to find out if
# some hosts have several ip-addresses.
function resolve_multiple_ip_hosts {
    entries=$(mktemp)
    temp_file=$(mktemp)
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
	"select host from hosts where host is not null order by host;" | uniq | tr '|' ' ' > "$entries"
    cat "$entries" | while read -r host; do
	if ! grep -q "^${host}$" "$dir"/function_resolve_multiple_ip_hosts.done; then
	    echo "Checking for more ip-addresses for host $host" >> "$dir"/run.log
	    host "$host" > "$temp_file"
	    if [ $? -eq 0 ]; then
		for var in $(grep "has address" "$temp_file" | sed 's/^.* //'); do
		    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where host = \"$host\" and ip_address = \"$var\";")
		    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
			echo "New ip-address found by resolving ip-address for host: $var $host" | tee -a "$dir"/run.log
			sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (host,ip_address,source) values (\"$host\",\"$var\",\"resolve-multiple\");"
			echo "resolve-multiple|$host|$var" >> "$dir"/host_sources.txt
		    fi
		done
	    fi
	    echo "$host" >> "$dir"/function_resolve_multiple_ip_hosts.done
	fi
    done
    #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
	#"select source, host, ip_address from hosts where source = 'resolve-multiple' order by host;" \
	#>> "$dir"/host_sources.txt
    rm "$temp_file"
    rm "$entries"
}

# This function is inspired by the ssl_san module of recon-ng
function get_ssl_info {
    entries=$(mktemp)
    temp_file=$(mktemp)
    temp_file2=$(mktemp)
    echo "Get more info from ssl certificates..." | tee -a "$dir"/run.log

    # Only query hosts having ip-addresses, i.e. don't query hosts only having
    # an unresolved hostname. Reasons:
    # 1.) since a dns lookup was performed earlier, then that means hostnames
    #     without ip-addresses won't resolve here either...
    # 2.) There can only be one SSL certificate per ip-address (no separate SSL
    #     certificates for virtual hosts running on the same server).
    # Note: wildcard certificates are not added since later searches based on hostnames
    # will screw up the search if there is a star in the hostname (e.g. *.domain.com).
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select ip_address from hosts where ip_address is not null order by host;" | uniq | tr '|' ' ' > "$entries"
    cat "$entries" | while read -r ip; do
	if ! grep -q "^${ip}$" "$dir"/function_get_ssl_info.done; then
	    if ! ipcalc -n "$ip" | grep -q "Private Internet"; then # skip private addresses
		if grep "$ip" "$dir"/nmap_scan.log | grep -q " 443/open"; then
		    echo "Getting more info from ssl certificates for $ip" >> "$dir"/run.log
		    timeout 10 openssl s_client -showcerts -connect $ip:443 < /dev/null 2> /dev/null > "$temp_file"
		    if [ $? -eq 0 ]; then
			cat "$temp_file" |openssl x509 -text > "$temp_file2"
			if grep -q "Subject Alternative Name" "$temp_file2"; then
			    echo -n "Alternative names for $ip: " >> "$dir"/alternative_names.txt
			    subj_alt_name=$(grep -A 10 "Subject Alternative Name" "$temp_file2" | grep "DNS:" | sed 's/DNS:/\nDNS:/g'|grep -v ^$|grep -v -E "^[ \t]*$"|sed 's/,//g'|sed 's/DNS://'|sed 's/[ \t]//g'|grep -v ^$ | grep -v -E "^\*" | tr '\n' ' ')
			    echo "$subj_alt_name" >> "$dir"/alternative_names.txt
			    for var in $subj_alt_name; do
				# For hosts not belonging to an ip-range of the organization
				# the host should be added if it matches an existing "middle"
				# name.
				belongs_to_org=0
				if ip_belongs_to_org "$ip"; then
				    belongs_to_org=1
				fi
				add=1;
				if [ $belongs_to_org -eq 0 ]; then
				    add=0
				    if name_matches_existing_middle_name "$var"; then
					add=1
				    fi
				fi
				if [ $add -eq 1 ]; then
				    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where host = \"$var\" and ip_address = \"$ip\";")
				    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
					echo "New host name found from SSL certificate: $ip $var" \
					    | tee -a "$dir"/run.log
					sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (host,ip_address,source) values (\"$var\",\"$ip\",\"ssl-cert\");"
					echo "ssl-cert|$var|$ip" >> "$dir"/host_sources.txt
				    fi
				fi
			    done
			fi
			if grep -q -E "CN[ \t]*=" "$temp_file2"; then
			    echo -n "Common names for $ip: " >> "$dir"/alternative_names.txt
			    common_names=$(grep "CN[ \t]*=" "$temp_file2" | sed 's/^.*CN[ \t]*=[ \t]*//'|sed 's/\/.*$//' | grep -v " " | grep -v -E "^\*" | sort | uniq | tr '\n' ' ' | sed 's/[ ]*$//')
			    echo "$common_names" >> "$dir"/alternative_names.txt
			    for var in $common_names; do
				# For hosts not belonging to an ip-range of the organization
				# the host should be added if it matches an existing "middle"
				# name.
				belongs_to_org=0
				if ip_belongs_to_org "$ip"; then
				    belongs_to_org=1
				fi
				add=1;
				if [ $belongs_to_org -eq 0 ]; then
				    add=0
				    if name_matches_existing_middle_name "$var"; then
					add=1
				    fi
				fi
				if [ $add -eq 1 ]; then
				    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where host = \"$var\" and ip_address = \"$ip\";")
				    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
					echo "New host name found from SSL certificate: $ip $var" | tee -a "$dir"/run.log
					sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (host,ip_address,source) values (\"$var\",\"$ip\",\"ssl-cert\");"
					echo "ssl-cert|$var|$ip" >> "$dir"/host_sources.txt
				    fi
				fi
			    done
			fi
			echo "$ip" >> "$dir"/function_get_ssl_info.done
		    fi
		fi
	    fi
	fi
    done
    #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select source, host, ip_address from hosts where source = 'ssl-cert' order by host;" >> "$dir"/host_sources.txt

    rm "$temp_file2"
    rm "$temp_file"
    rm "$entries"
}

#function get_google_ids_helper(ip_or_hostname,checked_urls_file,checked_ids_file)
function get_google_ids_helper {
    lookup=$1
    checked_urls_file=$2
    checked_ids_file=$3

    if ! grep -q "^${lookup}$" "$dir"/function_get_google_ids_helper.done; then
	temp_file=$(mktemp)
	temp_file2=$(mktemp)
	echo -n "" > "$temp_file"
	if grep "$ip" "$dir"/nmap_scan.log | grep -q " 443/open"; then
	    if ! grep -q "https://$lookup" "$checked_urls_file"; then
		echo "Looking up Google Analytics Id and Google AdSense Id for host https://$lookup" >> tee -a "$dir"/run.log
		run_command "" "use google_ids\nset url https://$lookup" true >> "$temp_file"
		echo "https://$lookup" >> "$checked_urls_file"
	    #else
	        #echo "Already checked url https://$lookup"
	    fi
	fi
	if grep "$ip" "$dir"/nmap_scan.log | grep -q " 80/open"; then
	    if ! grep -q "http://$lookup" "$checked_urls_file"; then
		echo "Looking up Google Analytics Id and Google AdSense Id for host http://$lookup" >> tee -a "$dir"/run.log
		run_command "" "use google_ids\nset url http://$lookup" true >> "$temp_file"
		echo "http://$lookup" >> "$checked_urls_file"
	    #else
	        #echo "Already checked url http://$lookup"
	    fi
	fi
        #for var in $(grep "Searching" "$temp_file" | grep "for other domains" | sed 's/^.* Searching //' \
	    #| sed 's/ for other domains.*$//'); do
	for var in $(grep "Found Code: " "$temp_file" | sed 's/^.* Found Code: //'); do
	    if ! grep -q "$var" "$checked_ids_file"; then
		echo -n "" > "$temp_file2"
		if echo "$var" | grep -q -E "^UA"; then # Google Analytics Id
		    echo "Looking for hosts sharing Google Analytics Id $var (for host $lookup)" | tee -a "$dir"/run.log
		    wget -O "$temp_file2" -o /dev/null "http://www.ewhois.com/ajax/reverse/?key=analytics&val=$var"
		    from="Google Analytics Id"
		else # Google AdSense Id
		    echo "Looking for hosts sharing Google AdSense Id $var (for host $lookup)" | tee -a "$dir"/run.log
		    wget -O "$temp_file2" -o /dev/null "http://www.ewhois.com/ajax/reverse/?key=adsense&val=$var"
		    from="Google AdSense Id"
		fi
		sites=$(cat "$temp_file2" | sed 's/\<div/\n<div/g'|grep "a href"|sed 's/^.*\<a href[ \t]*=[ \t]*[\\"\/]*//' \
		    | sed 's/[\\\/">].*$//' | tr '\n' ' ')
		if [ ! -z "$sites" ]; then
		    echo "Sites with the same $from ($var) as $lookup: $sites" >> "$dir"/google_ids.txt
		fi
		echo "$var" >> "$checked_ids_file"
	    #else
	        #echo "Already checked id $var"
	    fi
	done
	rm "$temp_file2"
	rm "$temp_file"
	echo "$lookup" >> "$dir"/function_get_google_ids_helper.done
    fi
}

# This function is inspired by the (non-working) google_ids module of recon-ng
function get_google_ids {
    entries=$(mktemp)
    checked_urls_file="$dir"/google_urls_checked.txt
    checked_ids_file="$dir"/google_ids_checked.txt
    echo "Get more info from Google Analytics Id and Google AdSense Id..." | tee -a "$dir"/run.log

    # Only query hosts having ip-addresses, i.e. don't query hosts only having
    # an unresolved hostname. Reason: since a dns lookup was performed earlier,
    # then that means hostnames without ip-addresses won't resolve here either...
    # However the lookup should still be performed using hostname and not ip-address
    # because several different virtual hosts could be running on the same ip.
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select ip_address, host from hosts where ip_address is not null order by host;" | uniq | tr '|' ' ' > "$entries"
    cat "$entries" | while read -r ip host; do
	if ! ipcalc -n "$ip" | grep -q "Private Internet"; then # skip private addresses
	    #echo "ip: $ip, host: $host"
	    if [ ! -z $host ]; then
		get_google_ids_helper "$host" "$checked_urls_file" "$checked_ids_file"
		# Also look up the ip-address in case a different virtual
		# host runs on the straight ip-address.
		get_google_ids_helper "$ip" "$checked_urls_file" "$checked_ids_file"
	    else
		get_google_ids_helper "$ip" "$checked_urls_file" "$checked_ids_file"
	    fi
	fi
    done

    #rm "$checked_ids_file"
    #rm "$checked_urls_file"
    rm "$entries"
}

# This function attempts to get more host names by checking if
# some of the already found ones are just aliases of another
# hostname.
function get_dns_aliases {
    temp_file=$(mktemp)
    echo "Checking for dns aliases of found hosts..." | tee -a "$dir"/run.log
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
    "select host, ip_address from hosts where host is not null and ip_address is not null order by host;" \
    | uniq | tr '|' ' ' \
    | while read -r host ip; do
	if ! grep -q "^${host}$" "$dir"/function_get_dns_aliases.done; then
	    host "$host" > "$temp_file"
	    if [ $? -eq 0 ]; then
		for var in $(grep " is an alias for " "$temp_file" | sed 's/^.* //' | sed 's/\.$//'); do
		    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
			"select count(*) from hosts where host = \"$var\";")
		    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		        # For hosts not belonging to an ip-range of the organization
		        # the host should be added if it matches an existing "middle"
		        # name.
			belongs_to_org=0
			if ip_belongs_to_org "$ip"; then
			    belongs_to_org=1
			fi
			add=1;
			if [ $belongs_to_org -eq 0 ]; then
			    add=0
			    if name_matches_existing_middle_name "$var"; then
				add=1
			    fi
			fi
			if [ $add -eq 1 ]; then
			    echo "New host name found by alias lookup ($host is an alias for $var)" \
				| tee -a "$dir"/run.log
			    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
				"insert into hosts (host,source) values (\"$var\",\"dns_alias_search\");"
			    echo "dns_alias_search|$var|" >> "$dir"/host_sources.txt
			fi
		    fi
		done
		echo "$host" >> "$dir"/function_get_dns_aliases.done
	    fi
	fi
    done
    #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
	#"select source, host, ip_address from hosts where source = 'dns_alias_search' order by host;" \
	#>> "$dir"/host_sources.txt
    rm "$temp_file"
}

# This function updates the host.source column of the database
function fix_sources {
    # NOTE: this one could not have been done using the (invisible)
    # rowid column of the hosts table. Reason: it actually changes
    # when fields are updated. However we could add an autoincrementing
    # primary key and use that instead of the hack below.
    echo "Adding the sources to the database..." | tee -a "$dir"/run.log
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = null;" 2> /dev/null
    cat "$dir"/host_sources.txt | sed 's/^\([^|]*\)|\([^|]*\)|\([^|]*\)$/\2|\3|\1/' | sort | uniq \
    | while read -r line; do
	#echo "LINE: $line"
	hostname=$(echo $line | cut -d'|' -f1)
	ip_address=$(echo $line | cut -d'|' -f2)
	source=$(echo $line | cut -d'|' -f3)
	if [ -z $hostname ]; then
	    if [ ! -z $ip_address ]; then
		#echo "hostname is null, ip address = $ip_address"
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"source\" || \", ip: $source\" where ip_address = \"$ip_address\" and host is null and source is not null;" 2> /dev/null
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"ip: $source\" where ip_address = \"$ip_address\" and host is null and source is null;" 2> /dev/null
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"source\" || \", ip: $source\" where ip_address = \"$ip_address\" and host is not null and source is not null;" 2> /dev/null
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"ip: $source\" where ip_address = \"$ip_address\" and host is not null and source is null;" 2> /dev/null
	    fi
	else
	    if [ ! -z $ip_address ]; then
		#echo "hostname = $hostname, ip_address = $ip_address"
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"source\" || \", name and ip: $source\" where ip_address = \"$ip_address\" and host = \"$hostname\" and source is not null;" 2> /dev/null
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"name and ip: $source\" where ip_address = \"$ip_address\" and host = \"$hostname\" and source is null;" 2> /dev/null
	    else
		#echo "hostname = $hostname, ip_address is null"
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"source\" || \", name: $source\" where ip_address is null and host = \"$hostname\" and source is not null;" 2> /dev/null
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"name: $source\" where ip_address is null and host = \"$hostname\" and source is null;" 2> /dev/null
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"source\" || \", name: $source\" where ip_address is not null and host = \"$hostname\" and source is not null;" 2> /dev/null
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = \"name: $source\" where ip_address is not null and host = \"$hostname\" and source is null;" 2> /dev/null
	    fi
	fi
    done
}

function fix_netranges {
    echo "Adding the netranges to the database..." | tee -a "$dir"/run.log
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set netrange = null;" 2> /dev/null
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select ip_address from hosts where ip_address is not null order by host;" | uniq \
    | while read -r ip; do
	if ipcalc -n "$ip" | grep -q "Private Internet"; then
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set netrange = \"private\" where ip_address = \"$ip\";" 2> /dev/null
	else
	    for range in $(cat "$dir"/whois_cidr_list.txt | grep -v -E "172.16.0.0/12|192.168.0.0/16|10.0.0.0/8"); do
		hostmin=$(ipcalc -n "$range" | grep -E "^Address:"|sed 's/ \+/ /'|cut -d' ' -f2)
		hostmax=$(ipcalc -n "$range" | grep -E "^Broadcast:"|sed 's/ \+/ /'|cut -d' ' -f2)
		if ip_within_range $ip $hostmin $hostmax; then
		    #echo "ip: $ip, range: $range, hostmin: $hostmin, hostmax: $hostmax"
		    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set netrange = \"$range\" where ip_address = \"$ip\";" 2> /dev/null
		    break
		fi
	    done
	fi
    done
}

function fix_netrange_owners {
    echo "Adding the netrange owners to the database..." | tee -a "$dir"/run.log
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set netrange_owner = null;" 2> /dev/null
    for ip in $(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select ip_address\
        from hosts where ip_address is not null and netrange_owner is null order\
        by ip_address;" | uniq); do
	if ipcalc -n "$ip" | grep -q "Private Internet"; then
	    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set netrange_owner = \"private\" where ip_address = \"$ip\" and netrange_owner is null;" 2> /dev/null
	else
	    cat "$dir"/netrange_list.txt | while read -r line; do
		#echo "LINE: $line"
		hostmin=$(echo $line | cut -d' ' -f1)
		hostmax=$(echo $line | cut -d' ' -f3)
		owner=$(echo $line | cut -d' ' -f4-)
		#echo "hostmin: $hostmin, hostmax: $hostmax, owner: $owner"
		if ip_within_range $ip $hostmin $hostmax; then
		    #echo "ip: $ip, owner: $owner, hostmin: $hostmin, hostmax: $hostmax"
		    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set netrange_owner = \"$owner\" where ip_address = \"$ip\" and netrange_owner is null;" 2> /dev/null
		    break
		fi
	    done
	fi
    done
}

function extract_hosts_from_spidered_pages_helper {
    #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "update hosts set source = null;" 2> /dev/null
    extract_host_middle_names

    # Extract the netranges that belong to the organization
    echo -n "" > "$dir"/organizations_own_netrange.txt
    for middle_name in $(cat "$dir"/hostname_middle_parts.txt); do
	grep -i $middle_name "$dir"/netrange_list.txt | \
	while read -r line; do
	    echo "$line" >> "$dir"/organizations_own_netrange.txt
	done
    done

    # Search for hostnames whose second last part exists
    # in the hosts table. Eg. if www.site.com exists
    # in the hosts table, then search for strings [a-z]+.site.[a-z]+.
    echo "Searching for hostnames similar to already found hosts..." | tee -a "$dir"/run.log
    echo -n "" > "$dir"/potential_hostnames_from_spidering.txt
    cat "$dir"/hostname_middle_parts.txt \
    | while read -r line; do
	find "$dir"/spidering -type f -exec grep -i -o -E \
	    "([^\"\/ >=\&]+\.)*[^\"\/ >=\&]+\.$line\.[^\"\/ >=<#\.<]+(\.[^\"\/ >=<#\.<]+)*" {} \; \
	    | grep -v -E "^Binary file " | grep -v "\&" | sed 's/[\.,]$//' | sed 's/'\''$//' \
	    | sed 's/[")<>]$//' | sed 's/^["(\<>]//' | grep -E "^[a-zA-Z0-9].*[a-zA-Z0-9]$" \
	    | tr 'A-Z' 'a-z'|sort|uniq >> "$dir"/potential_hostnames_from_spidering.txt
	find "$dir"/spidering_unpacked -type f -exec grep -i -o -E \
	    "([^\"\/ >=\&]+\.)*[^\"\/ >=\&]+\.$line\.[^\"\/ >=<#\.<]+(\.[^\"\/ >=<#\.<]+)*" {} \; \
	    | grep -v -E "^Binary file " | grep -v "\&" | sed 's/[\.,]$//' | sed 's/'\''$//' \
	    | sed 's/[")<>]$//' | sed 's/^["(\<>]//' | grep -E "^[a-zA-Z0-9].*[a-zA-Z0-9]$" \
	    | tr 'A-Z' 'a-z'|sort|uniq >> "$dir"/potential_hostnames_from_spidering.txt
	cat "$dir"/spidered_imagestrings.txt | grep -i -o -E \
	    "([^\"\/ >=\&]+\.)*[^\"\/ >=\&]+\.$line\.[^\"\/ >=<#\.<]+(\.[^\"\/ >=<#\.<]+)*" \
	    | grep -v -E "^Binary file " | grep -v "\&" | sed 's/[\.,]$//' | sed 's/'\''$//' \
	    | sed 's/[")<>]$//' | sed 's/^["(\<>]//' | grep -E "^[a-zA-Z0-9].*[a-zA-Z0-9]$" \
	    | tr 'A-Z' 'a-z'|sort|uniq >> "$dir"/potential_hostnames_from_spidering.txt
	cat "$dir"/spidered_pdfs.txt | grep -i -o -E \
	    "([^\"\/ >=\&]+\.)*[^\"\/ >=\&]+\.$line\.[^\"\/ >=<#\.<]+(\.[^\"\/ >=<#\.<]+)*" \
	    | grep -v -E "^Binary file " | grep -v "\&" | sed 's/[\.,]$//' | sed 's/'\''$//' \
	    | sed 's/[")<>]$//' | sed 's/^["(\<>]//' | grep -E "^[a-zA-Z0-9].*[a-zA-Z0-9]$" \
	    | tr 'A-Z' 'a-z'|sort|uniq >> "$dir"/potential_hostnames_from_spidering.txt
    done
    cat "$dir"/potential_hostnames_from_spidering.txt | sort | uniq | while read -r line; do
	host $line > /dev/null
	if [ $? -eq 0 ]; then
	    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where host = \"$line\";")
	    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		echo "New host name found by spidering website: $line" | tee -a "$dir"/run.log
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (host,source) values (\"$line\",\"spidering-webpage\");"
		echo "spidering-webpage|$line|" >> "$dir"/host_sources.txt
	    fi
	fi
    done

    # Search for ip-addresses that belong to an ip-range
    # that's identified to belong to the client organization.
    echo "Searching for ip-addresses belonging to known ip-ranges..." | tee -a "$dir"/run.log
    echo -n "" > "$dir"/potential_ip_addresses_from_spidering.txt
    find "$dir"/spidering -type f -exec \
	grep -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])' {} \; \
	| grep -v -E "^Binary file " \
	| grep -v -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])[\.a-zA-Z]' \
	| grep -o -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])' | sort | uniq >> "$dir"/potential_ip_addresses_from_spidering.txt
    find "$dir"/spidering_unpacked -type f -exec \
	grep -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])' {} \; \
	| grep -v -E "^Binary file " \
	| grep -v -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])[\.a-zA-Z]' \
	| grep -o -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])' | sort | uniq >> "$dir"/potential_ip_addresses_from_spidering.txt
    cat "$dir"/spidered_imagestrings.txt \
	| grep -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])' \
	| grep -v -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])[\.a-zA-Z]' \
	| grep -o -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])' | sort | uniq >> "$dir"/potential_ip_addresses_from_spidering.txt
    cat "$dir"/spidered_pdfs.txt \
	| grep -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])' \
	| grep -v -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])[\.a-zA-Z]' \
	| grep -o -E '((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])' | sort | uniq >> "$dir"/potential_ip_addresses_from_spidering.txt
    cat "$dir"/potential_ip_addresses_from_spidering.txt | sort | uniq | while read -r line; do
	#if ! ipcalc -n "$line" | grep -q "Private Internet"; then # skip private addresses
	    # There are so many false positives for ip-addresses, so
	    # make sure that they belong to an ip-range that is
	    # identified to belong to the organization.
	    cat "$dir"/organizations_own_netrange.txt | while read -r netrange; do
	        #echo "LINE: $line"
		hostmin=$(echo $netrange | cut -d' ' -f1)
		hostmax=$(echo $netrange | cut -d' ' -f3)
	        #echo "hostmin: $hostmin, hostmax: $hostmax, ip: $line"
		if ip_within_range $line $hostmin $hostmax; then
		    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where ip_address = \"$line\";")
		    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
			echo "New ip-address found by spidering website: $line" | tee -a "$dir"/run.log
		        sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (ip_address,source) values (\"$line\",\"spidering-webpage\");"
			echo "spidering-webpage||$line" >> "$dir"/host_sources.txt
			break
		    fi
		fi
	    done
	#fi
    done

    # Search for the strings "http://" and "https://" and "ftp://"
    echo "Searching for strings http://, https:// and ftp://..." | tee -a "$dir"/run.log
    echo -n "" > "$dir"/potential_protocol_strings_spidering.txt
    find "$dir"/spidering -type f -exec grep -i "http://" {} \; | tr 'A-Z' 'a-z' \
	| grep -v "Binary file" | sed 's/^.*\(http:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^http://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    find "$dir"/spidering_unpacked -type f -exec grep -i "http://" {} \; | tr 'A-Z' 'a-z' \
	| grep -v "Binary file" | sed 's/^.*\(http:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^http://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    cat "$dir"/spidered_imagestrings.txt \
	| grep -i "http://" | tr 'A-Z' 'a-z' | sed 's/^.*\(http:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^http://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    cat "$dir"/spidered_pdfs.txt \
	| grep -i "http://" | tr 'A-Z' 'a-z' | sed 's/^.*\(http:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^http://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    find "$dir"/spidering -type f -exec grep -i "https://" {} \; | tr 'A-Z' 'a-z' \
	| grep -v "Binary file" | sed 's/^.*\(https:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^https://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    find "$dir"/spidering_unpacked -type f -exec grep -i "https://" {} \; | tr 'A-Z' 'a-z' \
	| grep -v "Binary file" | sed 's/^.*\(https:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^https://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    cat "$dir"/spidered_imagestrings.txt \
	| grep -i "https://" | tr 'A-Z' 'a-z' | sed 's/^.*\(https:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^https://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    cat "$dir"/spidered_pdfs.txt \
	| grep -i "https://" | tr 'A-Z' 'a-z' | sed 's/^.*\(https:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^https://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    find "$dir"/spidering -type f -exec grep -i "ftp://" {} \; | tr 'A-Z' 'a-z' \
	| grep -v "Binary file" | sed 's/^.*\(ftp:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^ftp://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    find "$dir"/spidering_unpacked -type f -exec grep -i "ftp://" {} \; | tr 'A-Z' 'a-z' \
	| grep -v "Binary file" | sed 's/^.*\(ftp:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^ftp://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    cat "$dir"/spidered_imagestrings.txt \
	| grep -i "ftp://" | tr 'A-Z' 'a-z' | sed 's/^.*\(ftp:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^ftp://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    cat "$dir"/spidered_pdfs.txt \
	| grep -i "ftp://" | tr 'A-Z' 'a-z' | sed 's/^.*\(ftp:\/\/[a-zA-Z0-9\.]\+\).*$/\1/' \
	| grep "^ftp://" | sort | uniq >> "$dir"/potential_protocol_strings_spidering.txt
    cat "$dir"/potential_protocol_strings_spidering.txt \
    | sed 's/^http:\/\///'|sed 's/https:\/\///'|sed 's/ftp:\/\///' \
    | sed 's/\.$//' | sed 's/:.*$//' | grep -v "[<>]" | grep -v " " \
    | grep -v -E "^localhost$" | sort | uniq \
    | while read -r line; do
	if echo $line | grep -q -E '^((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])$'; then
	    # If this is an ip-address, then add it if it belongs to
	    # a range that's identified for the target organiation.
	    #if ! ipcalc -n "$line" | grep -q "Private Internet"; then # skip private addresses
	        # There are so many false positives for ip-addresses, so
	        # make sure that they belong to an ip-range that is
	        # identified to belong to the organization.
	        cat "$dir"/organizations_own_netrange.txt | while read -r netrange; do
	            #echo "LINE: $line"
		    hostmin=$(echo $netrange | cut -d' ' -f1)
		    hostmax=$(echo $netrange | cut -d' ' -f3)
	            #echo "hostmin: $hostmin, hostmax: $hostmax, ip: $line"
		    if ip_within_range $line $hostmin $hostmax; then
			exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from 
hosts where ip_address = \"$line\";")
			if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
			    echo "New ip-address found by spidering website: $line" | tee -a "$dir"/run.log
		            sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (ip_address,source) values (\"$line\",\"spidering-webpage\");"
			    echo "spidering-webpage||$line" >> "$dir"/host_sources.txt
			    break
			fi
		    fi
		done
	    #fi
	else
	    # Make sure that the "middle" part of the hostname exists in the database.
	    # For example if www.site.com exists in the database, then we should
	    # add the new site abc.site.ru, but www.sans.org should not be added.
	    if cat "$dir"/hostname_middle_parts.txt \
	    | grep -q "^$(echo $line | awk -F. '{ print $(NF-1) }')$"; then
		#echo "line: $line"
		host $line > /dev/null
		if [ $? -eq 0 ]; then
		    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where host = \"$line\";")
		    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
			echo "New host name found by spidering website: $line" | tee -a "$dir"/run.log
		        sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (host,source) values (\"$line\",\"spidering-webpage\");"
			echo "spidering-webpage|$line|" >> "$dir"/host_sources.txt
		    fi
		fi
	    else
		# Check if its ip address belongs to an ip-range that
		# belongs to the organization.
		#echo "Check if $line belongs to a known ip-range"
		raw_line=$(host "$line")
		echo "  raw_line: $raw_line" | grep -q "has address"
		if [ $? -eq 0 ]; then
		    for ip in $(echo "$raw_line" | grep "has address" | awk '{ print $NF}'); do
			#echo "    ip: $ip"
	                #if ! ipcalc -n "$ip" | grep -q "Private Internet"; then # skip private addresses
	                    cat "$dir"/organizations_own_netrange.txt | while read -r netrange; do
	                        #echo "ip: $ip"
				hostmin=$(echo $netrange | cut -d' ' -f1)
				hostmax=$(echo $netrange | cut -d' ' -f3)
	                        #echo "hostmin: $hostmin, hostmax: $hostmax, ip: $ip"
				if ip_within_range $ip $hostmin $hostmax; then
				    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts where host = \"$line\";")
				    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
					echo "New host name found by spidering website: $line (because ip $ip belongs to range $netrange)" | tee -a "$dir"/run.log
					sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "insert into hosts (host,source) values (\"$line\",\"spidering-webpage\");"
					echo "spidering-webpage|$line|" >> "$dir"/host_sources.txt
					break
				    fi
				fi
			    done
	                #fi
		    done
		fi
	    fi
	fi
    done

    rm "$dir"/hostname_middle_parts.txt
    rm "$dir"/organizations_own_netrange.txt
    #sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select source, host, ip_address from hosts where source = 'spidering-webpage' order by host;" >> "$dir"/host_sources.txt
}

function extract_hosts_from_spidered_pages {
    # unpack certain files
    echo "Unpacking packed files found during spidering..." | tee -a "$dir"/run.log
    temp_dest="$dir"/spidering_unpacked
    mkdir "$temp_dest" 2> /dev/null
    find "$dir"/spidering -type f -iname '*.zip' -exec cp {} "$temp_dest"/ \;
    find "$dir"/spidering -type f -iname '*.tar' -exec cp {} "$temp_dest"/ \;
    find "$dir"/spidering -type f -iname '*.gz' -exec cp {} "$temp_dest"/ \;
    find "$dir"/spidering -type f -iname '*.tgz' -exec cp {} "$temp_dest"/ \;
    find "$dir"/spidering -type f -iname '*.jar' -exec cp {} "$temp_dest"/ \;
    cd "$temp_dest"
    # For unzipping add a dummy password to make sure that it doesn't hang waiting
    # for a user provided password. Also add the -B switch to make sure that it
    # automatically overwrites existing files, saving a backup of the overwritten
    # file.
    find . -iname '*.zip' -exec unzip -q -B -P dummy {} \;
    find . -iname '*.gz' -exec gunzip {} \;
    find . -iname '*.tgz' -exec tar -xzf {} \;
    find . -iname '*.tar' -exec tar -xf {} \;
    find . -iname '*.jar' -exec jar -xf {} \;
    # It might also be possible that some of these files contain more zip files, so lets go
    # through this again
    find . -iname '*.zip' -exec unzip -q -B -P dummy {} \;
    find . -iname '*.gz' -exec gunzip {} \;
    find . -iname '*.tgz' -exec tar -xzf {} \;
    find . -iname '*.tar' -exec tar -xf {} \;
    find . -iname '*.jar' -exec jar -xf {} \;
    cd - > /dev/null

    # search in images:
    echo "Extracting strings from images found during spidering..." | tee -a "$dir"/run.log
    temp_dest="$dir"/spidered_imagestrings.txt
    echo -n "" > "$temp_dest"
    find "$dir"/spidering -type f -iname '*.jpg' -exec exiftool {} \; >> "$temp_dest"
    find "$dir"/spidering -type f -iname '*.jpeg' -exec exiftool {} \; >> "$temp_dest"
    find "$dir"/spidering -type f -iname '*.png' -exec exiftool {} \; >> "$temp_dest"
    find "$dir"/spidering -type f -iname '*.gif' -exec exiftool {} \; >> "$temp_dest"
    find "$dir"/spidering -type f -iname '*.ico' -exec exiftool {} \; >> "$temp_dest"

    find "$dir"/spidering_unpacked -type f -iname '*.jpg' -exec exiftool {} \; >> "$temp_dest"
    find "$dir"/spidering_unpacked -type f -iname '*.jpeg' -exec exiftool {} \; >> "$temp_dest"
    find "$dir"/spidering_unpacked -type f -iname '*.png' -exec exiftool {} \; >> "$temp_dest"
    find "$dir"/spidering_unpacked -type f -iname '*.gif' -exec exiftool {} \; >> "$temp_dest"
    find "$dir"/spidering_unpacked -type f -iname '*.ico' -exec exiftool {} \; >> "$temp_dest"

    # search in pdfs:
    temp_dest="$dir"/spidered_pdfs.txt
    echo -n "" > "$temp_dest"
    echo "Extracting texts from pdf's found during spidering..." | tee -a "$dir"/run.log
    find "$dir"/spidering -type f -iname '*.pdf' -exec pdfinfo -meta {} \; 2> /dev/null >> "$temp_dest"
    find "$dir"/spidering -type f -iname '*.pdf' -exec pdftotext {} - \;  2> /dev/null >> "$temp_dest"
    find "$dir"/spidering_unpacked -type f -iname '*.pdf' -exec pdfinfo -meta {} \; 2> /dev/null >> "$temp_dest"
    find "$dir"/spidering_unpacked -type f -iname '*.pdf' -exec pdftotext {} - \;  2> /dev/null >> "$temp_dest"

    # Finally do the actual host extraction
    extract_hosts_from_spidered_pages_helper
}

function spider_webpage {
    url=$1
    if ! grep -q -E "^${url}$" "$dir"/spidered.txt; then
	echo "Spidering webpage of $url" | tee -a "$dir"/run.log
	wget -r -w 1 -nv -a "$dir"/spidering.log --page-requisites --no-check-certificate --protocol-directories --follow-ftp "$url"
	echo "$url" >> "$dir"/spidered.txt
	echo "true" > "$dir"/new_spidered_info.txt
    fi
}

function spider_webpages {
    echo "Spidering webpages..." | tee -a "$dir"/run.log
    echo -n "" > "$dir"/new_spidered_info.txt
    mkdir "$dir"/spidering 2> /dev/null
    cd "$dir"/spidering
    #rm "$dir"/spidered.txt

    # First spider hosts that have port 80 and 443 open (both
    # on hostname and directly on ip-address).
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select ip_address from hosts where ip_address is not null order by host;" \
    | while read -r ip; do
	#echo "ip: $ip"
	if ! ipcalc -n "$ip" | grep -q "Private Internet"; then # skip private addresses
	    #echo "  is public address"
	    if grep "$ip" "$dir"/nmap_scan.log | grep -q " 80/open"; then
		#echo "    has port 80 open"
		spider_webpage "http://$ip"
		for var in $(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select host from hosts where ip_address = \"$ip\" order by host;"); do
		    spider_webpage "http://$var"
		done
	    fi
	    if grep "$ip" "$dir"/nmap_scan.log | grep -q " 443/open"; then
		#echo "    has port 443 open"
		spider_webpage "https://$ip"
		for var in $(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select host from hosts where ip_address = \"$ip\" order by host;"); do
		    spider_webpage "https://$var"
		done
	    fi
	fi
    done
    cd - > /dev/null

    if grep -q -E "^true$" "$dir"/new_spidered_info.txt; then
	extract_hosts_from_spidered_pages
    fi
}


run_command "" "set domain $domain" false

# Add a database column for source where we store the source where
# the hostname was found. Note that this column will be overwritten
# by dns resolvation, so therefore this information is also stored
# in the file host_sources.txt.
sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "alter table hosts add column source text;" 2> /dev/null
sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "alter table hosts add column netrange text;" 2> /dev/null
sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "alter table hosts add column netrange_owner text;" 2> /dev/null

function run {
    simple_host_searches
    run_command "Looking up ip-addresses of hosts..." "use dns/resolve" false
    resolve_multiple_ip_hosts
    dns_brute_force
    run_command "Looking up ip-addresses of hosts..." "use dns/resolve" false
    resolve_multiple_ip_hosts

    find_whois_netranges
    #subnets=$(cat "$dir"/fierce_subnets.txt | tr '\n' ' ')
    subnets=$(cat "$dir"/whois_cidr_list.txt | grep -v -E "172.16.0.0/12|192.168.0.0/16|10.0.0.0/8" | tr '\n' ' ')

    # Search for hosts on subnets at shodan
    shodan_subnet_search "$subnets"

    # Scan all subnets that whois found using nmap. Note: fierce also found
    # a list of subnets, but the whois output is more accurate.
    nmap_subnet_scan "$subnets"

    # Make reverse ip lookups of the found subnets
    reverse_ip_lookups

    # Check for other hosts on the same servers
    find_virtual_hosts_on_same_ip
    run_command "Looking up ip-addresses of hosts..." "use dns/resolve" false
    resolve_multiple_ip_hosts

    # Get more info from the ssl certificate
    get_ssl_info

    # Geolocate hosts. Before doing that however, we need to resolve host names
    # to ip addresses for any new hosts that are found.
    run_command "Looking up ip-addresses of hosts..." "use dns/resolve" false
    resolve_multiple_ip_hosts
    geolocate_hosts

    # Get domains having the same Google Analytics or Google AdSense ID.
    get_google_ids

    get_dns_aliases
    run_command "Looking up ip-addresses of hosts..." "use dns/resolve" false
    resolve_multiple_ip_hosts
    spider_webpages
}

nbr_hosts=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts;")
run
nbr_hosts_after=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from hosts;")
echo "Number of new hosts found during this run: $(($nbr_hosts_after-$nbr_hosts))" | tee -a "$dir"/run.log
if [ $nbr_hosts_after -gt $nbr_hosts ]; then
    echo "You might want to do another round." | tee -a "$dir"/run.log
fi


fix_sources
fix_netranges
fix_netrange_owners

# TODO: add usage of the following recon-ng modules (perhaps I can make a separate
# script find_vulns.sh for these):
#
# builtwith:
# get a list of used server side technologies + the used framework (eg. php or j2ee, etc.)
#
# punkspider:
# returns information if some web vulnerability is known for the target site
#
# wascompanyhacked:
# searches twitter for breach related hash tags
#
# whatweb:
# gets information about what web technologies the found hosts are running
#
# asafaweb:
# asafaweb tests for some common vulnerabilities found in asp.net websites. Can tell something
# also for non-asp.net websites. Note: this test is so good that it can be a good idea to also
# run it manually from their websites, because the complete report shows more information than
# the asafaweb module in recon-ng.
#
# ipvoid:
# checks security information about ip-addresses by checking different blacklists on the
# internet. The module doesn't really work, however, all the ip-addresses can manually be
# checked at http://www.ipvoid.com/scan/64.57.244.54, etc.
#
# malwaredomain:
# checks malwaredomainlist.com to determine if malware has been detected on the given domain.
# Note: it might be a good idea to also check the following manually: http://wepawet.iseclab.org/
# (there seems to be no recon-ng plugin for this one, but we can manually enter a url to check).
#
# mywot:
# Checks mywot.com site for information about the security of a domain. Note: the host to check
# is taken from the DOMAIN option and not from the database.
#
# netbios:
# gathers NETBIOS information from w3dt.net. Note: it might be a good idea to also use some of
# the tools at https://w3dt.net/, for example there is a DNS server fingerprinting tool that
# attempts to determine the version of the DNS software in the name servers + HTTPRecon
# (fingerprinting of the webserver) + default password lookup for hardware / software
#
# netcraft_history:
# gets history information about the target site from netcraft. Note: it might be a good idea
# to also manually check the result page in a web browser because the netcraft site returns
# more information (e.g. about server-side technologies) than what this recon-ng module shows
# (the url to use is printed out by this plugin).
#
# open_resolvers:
# checks if any open recursive dns resolvers exist on the target network
#
# urlvoid:
# checks security information about hosts by checking different blacklists on the internet.
# It seems like "www." cannot be put in front of the hostname and for that reason this module
# fails. However all the urls can manually be checked at http://www.urlvoid.com/
#
# xssed:
# checks known xss vulnerabilities from xssed.com and displays a list of them
#
# 


# TODO: to this report we could also add such hosts from the
# reverse_ip_lookup that weren't added to the database because the
# subnet wasn't owned by the target organization and the name didn't
# match any found "middle" name. At least for sijoitustutkimus their
# mail server is in a subnet not owned by the organization and its
# name doesn't match any found "middle" name. Same thing goes for
# the bing ip search.

# Make report
echo "Generating report to $dir/report.txt ..." | tee -a "$dir"/run.log
# list DNS servers:
if [ -e "$dir"/dns_servers.txt ]; then
    echo "DNS Servers for ${domain}:" | tee -a "$dir"/report.txt
    cat "$dir"/dns_servers.txt | sort | uniq | tee -a "$dir"/report.txt
    echo | tee -a "$dir"/report.txt
fi
#if [ -e "$dir"/fierce_subnets.txt ]; then
#    echo "Subnets that fierce found:" | tee -a "$dir"/report.txt
#    cat "$dir"/fierce_subnets.txt | tee -a "$dir"/report.txt
#    echo | tee -a "$dir"/report.txt
#fi
if [ -e "$dir"/whois_cidr_list.txt ]; then
    echo "Subnets that whois found:" | tee -a "$dir"/report.txt
    cat "$dir"/whois_cidr_list.txt | tee -a "$dir"/report.txt
    echo | tee -a "$dir"/report.txt
fi
# list found hosts
run_command "Found hosts (ordered by hostname):" "query select * from hosts order by host;" true \
 | tee -a "$dir"/report.txt
echo | tee -a "$dir"/report.txt
run_command "Found hosts (ordered by ip):" "query select * from hosts order by ip_address;" true \
 | tee -a "$dir"/report.txt
echo | tee -a "$dir"/report.txt

if [[ -f "$dir"/google_ids.txt ]] && [[ "$(cat "$dir"/google_ids.txt | wc -l)" != "0" ]]; then
    echo | tee -a "$dir"/report.txt
    echo "Sites having the same Google Analytics Id or same Google AdSense Id (might be" | tee -a "$dir"/report.txt
    echo "administrated or coded by the same people):" | tee -a "$dir"/report.txt
    cat "$dir"/google_ids.txt | tee -a "$dir"/report.txt
fi


# make better usage of the parameters: veryfast should be very fast, and then there should be a parameter veryslow
# which tekee toisen kierroksen jossa käytetään:
# time ./find_hosts.sh example.com veryfast
# etc.
# => TAI: vähintään pitää raporttiin listata nämä toiset domainit ja ehdottaa, että voisi ajaa uuden skannin
# niillä (ei välttämättä toimi niin hyvin yleisesti ottaen jos ajaa näitä automaattisesti koska esim.
# sijoitustutkimuksen kohdalla ne ei omista subnettiä joissa www.sijoitustutkimus pyörii ja sitten tulee
# hirveä määrä niitä domainejä jotka eivät liity millään lailla sijoitustutkimukseen).

# Ev. kolla igen på api/google_site, varför den inte returnerar något alls. Onkohan tässä sama
# ongelma kuin bingin kohdalla, että pitää ensin subscribata johonkin datasettiin? Vai saako
# hosteja jos ajaa tämän sellstar.fi:stä (avain taisi olla generoitu ajettavaksi sellstar.fi:stä).

#rm -rf "$dir"
