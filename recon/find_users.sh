#!/bin/bash

# Script for finding users and email addresses of a target organization.
# Author: John Bergbom

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

if [ ! -d "$dir" ]; then
    mkdir "$dir"
fi
echo "Using the recon-ng workspace $workspace" | tee -a "$dir"/run.log
echo "Working directory: $dir" | tee -a "$dir"/run.log


# The params parameter is specified like this:
# "-o name1=value1 -o name2=value2 ..."
#function run_command(msg,command,verbose,params) {
function run_command {
    msg=$1
    command=$2
    verbose=$3
    parameters=$4
    if [ "$msg" != "" ]; then
        echo "$msg"
    fi
    cd /usr/local/recon-ng
    if [ "$verbose" == "true" ]; then
	./recon-cli -w "$workspace" -m "$command" $parameters | tee -a "$dir"/run.log
    else
	./recon-cli -w "$workspace" -m "$command" $parameters >> "$dir"/run.log
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

# This function finds usernames from meta info of pdf files found when
# spidering the website.
function find_users_from_spidered_pdfs {
    if ! grep -q "^find_users_from_spidered_pdfs$" "$dir"/user_searches.done; then
	echo "Finding users from spidered pdf files..."
	temp_list=$(mktemp)
	find "$dir"/spidering -type f -iname '*.pdf' -exec pdfinfo -meta {} \; 2> /dev/null \
	    | grep -E "^Author:" |sed 's/^Author://'|sed 's/^[ \t]*//' >> "$temp_list"
	find "$dir"/spidering_unpacked -type f -iname '*.pdf' -exec pdfinfo -meta {} \; 2> /dev/null \
	    | grep -E "^Author:" |sed 's/^Author://'|sed 's/^[ \t]*//' >> "$temp_list"
	cat "$temp_list" |sort|uniq|grep -v -E "^$|^\*$|^\.$|^Copyright [0-9]"|grep -v -i "^examplecorp$"|grep -v -i "Copyright example Corp[^ ]* All rights reserved\.$"|grep -v -i -E "^updated [0-9/-]+$" | grep " " > "$dir/found_full_names.txt"
	cat "$temp_list" |sort|uniq|grep -v -E "^$|^\*$|^\.$|^Copyright [0-9]"|grep -v -i "^examplecorp$"|grep -v -i "Copyright example Corp[^ ]* All rights reserved\.$"|grep -v -i -E "^updated [0-9/-]+$" | grep -v " " > "$dir/found_user_names.txt"
	rm "$temp_list"
	echo "find_users_from_spidered_pdfs" >> "$dir"/user_searches.done
    fi
}

function find_emails_from_spidered_webpages {
    if ! grep -q "^find_emails_from_spidered_webpages$" "$dir"/user_searches.done; then
	echo "Finding email addresses from spidered web pages..."
	#echo -n "" > "$dir/found_emails.txt"
	extract_found_domains
	tempfile=$(mktemp)
	find "$dir"/spidering -type f -exec grep -E -o "[^ @]+@[^ ]+" {} \; \
	    | grep -a -v -E "^Binary file " | sed 's/\(@[^ (),“"”<>:]*\).*$/\1/' \
	    | sed 's/^.*[ @(),“"”<>:]\([^ @(),“"”<>]\+@\)/\1/' | grep -a -v "@$" \
	    | grep -a -E "@[a-zA-Z0-9-]+\." | grep -a -o -E "[a-zA-Z0-9\.-]+@[a-zA-Z0-9\.-]+" \
	    | grep -a -v -E "\.$" | tr 'A-Z' 'a-z' | sort | uniq \
	    | grep -f "$dir"/found_domains.txt >> "$tempfile"
	find "$dir"/spidering_unpacked -type f -exec grep -E -o "[^ @]+@[^ ]+" {} \; \
	    | grep -a -v -E "^Binary file " | sed 's/\(@[^ (),“"”<>:]*\).*$/\1/' \
	    | sed 's/^.*[ @(),“"”<>:]\([^ @(),“"”<>]\+@\)/\1/' | grep -a -v "@$" \
	    | grep -a -E "@[a-zA-Z0-9-]+\." | grep -a -o -E "[a-zA-Z0-9\.-]+@[a-zA-Z0-9\.-]+" \
	    | grep -a -v -E "\.$" | tr 'A-Z' 'a-z' | sort | uniq \
	    | grep -f "$dir"/found_domains.txt >> "$tempfile"
	cat "$dir"/spidered_imagestrings.txt | grep -E -o "[^ @]+@[^ ]+" | sed 's/^[^>]*>//' \
	    | sed 's/\(@[^ <]\+\)<.*$/\1/' | sed 's/\.$//' | sed 's/[(),“"”]//g' | tr 'A-Z' 'a-z' | sort | uniq \
	    | grep -f "$dir"/found_domains.txt >> "$tempfile"
	cat "$dir"/spidered_pdfs.txt | grep -E -o "[^ @]+@[^ ]+" | sed 's/^[^>]*>//' \
	    | sed 's/\(@[^ <]\+\)<.*$/\1/' | sed 's/\.$//' | sed 's/[(),“"”]//g' | tr 'A-Z' 'a-z' | sort | uniq \
	    | grep -f "$dir"/found_domains.txt >> "$tempfile"
	cat "$tempfile" | sort | uniq > "$dir/found_emails.txt"
	rm "$tempfile"
	rm "$dir"/found_domains.txt
	echo "find_emails_from_spidered_webpages" >> "$dir"/user_searches.done
    fi
}

function find_twitter_accounts_from_spidered_webpages {
    if ! grep -q "^find_twitter_accounts_from_spidered_webpages$" "$dir"/user_searches.done; then
	echo "Finding twitter accounts from spidered web pages..."
	#echo -n "" > "$dir"/spidered_potential_twitter_accounts.txt
	tempfile=$(mktemp)
	find "$dir"/spidering -type f -exec grep -E -o "@[^ ]+" {} \; >> "$tempfile"
	find "$dir"/spidering_unpacked -type f -exec grep -E -o "@[^ ]+" {} \; \
	    >> "$tempfile"
	cat "$dir"/spidered_imagestrings.txt | grep -E -o "@[^ ]+" >> "$tempfile"
	cat "$dir"/spidered_pdfs.txt | grep -E -o "@[^ ]+" >> "$tempfile"
	# Remove some common strings known to have the @ symbol in front or
	# otherwise false positive.
	cat "$tempfile" | grep "^@[a-zA-Z0-9-]" | grep -o "@[a-zA-Z0-9\.-]\+" | grep -v -E "@before$|@charset$|@class$|@constructor$|@copyright$|@data$|@example$|@font-face$|@import$|@inherits$|@keyframes$|@license$|@media$|@method$|keyframes$|@package$|@page$|@param$|@result$|@return$|@returns$|@since$|@subpackage$|@twitter$|@version$|@mobileusers$|@domain$|@author$|@action$|character$|^@server$" | sort | uniq > "$dir"/spidered_potential_twitter_accounts.txt
	rm "$tempfile"
	echo "find_twitter_accounts_from_spidered_webpages" >> "$dir"/user_searches.done
    fi

    if ! grep -q "^verified_twitter_accounts_from_spidered_webpages$" "$dir"/user_searches.done; then
	echo "Verifying twitter accounts from spidered web pages..."
	echo -n "" > "$dir"/found_twitter_accounts.txt
	echo -n "" > "$dir"/found_twitter_communication.txt
	tempfile=$(mktemp)

	# There are very many false positives when just making a dumb search.
	# It's hard to know with programming logic that "@myhandle" is more likely
	# to be a real twitter account than "@mhndlyae". Therefore some heuristics
	# is applied to minimize the false positives. However, this heuristics can
	# easily also remove some real twitter accounts. Heuristics:
	# 1.) Remove all hits that have a dot (.) in them.
	# 2.) Remove all hits that don't have at least three small case letters in succession.
	# 3.) Remove all hits that don't have at least one vocal in them.
	# 4.) Remove all hits that have certain hardcoded values (actually done
	#     already above).
	# 5.) Remove all hits that are shorter than 6 characters.
	cat "$dir"/spidered_potential_twitter_accounts.txt | grep -v "\." | grep -E "[a-z][a-z][a-z]" \
	| grep "[aeiouy]" | grep "......"|sort|uniq | \
	while read -r line; do
	    run_command "" "recon/contacts/gather/http/api/twitter" true "-o handle=$line" > "$tempfile"
	    nbr_lines=$(grep -v -E "^HANDLE|Searching for users|name or service not known" "$tempfile" | wc -l)
	    if [ $nbr_lines -gt 0 ]; then
		echo "$line" >> "$dir"/found_twitter_accounts.txt
		cat "$tempfile" >> "$dir"/found_twitter_communication.txt
	    fi
	done
	rm "$tempfile"
	echo "verified_twitter_accounts_from_spidered_webpages" >> "$dir"/user_searches.done
    fi
}

function extract_potential_email_addresses {
    if ! grep -q "^extract_potential_email_addresses$" "$dir"/user_searches.done; then
	echo "Extracting potential email addresses..."
	#echo -n "" >> "$dir"/potential_email_addresses.txt
	tempfile=$(mktemp)
	grep -E "^first.last@|^firstname.lastname@|^first_last@|^firstname_lastname@|^etu.suku@|^etunimi.sukunimi@|^for.efter@|^fornamn.efternamn@" "$dir/found_emails.txt" \
	    | sed 's/^[^@]\+@//' | sort | uniq > "$tempfile"
	if grep -q -E "^first.last@|^firstname.lastname@" "$dir/found_emails.txt"; then
	    separator="."
	elif grep -q -E "^first_last@|^firstname_lastname@" "$dir/found_emails.txt"; then
	    separator="_"
	elif grep -q -E "^etu.suku@|^etunimi.sukunimi@" "$dir/found_emails.txt"; then
	    separator="_"
	elif grep -q -E "^for.efter@|^fornamn.efternamn@" "$dir/found_emails.txt"; then
	    separator="_"
	fi
	if [ ! -z "$separator" ]; then
	    cat "$dir"/found_full_names.txt | \
	    while read -r line; do
		email_first_part=$(echo "$line" | sed "s/ \+/$separator/g" | sed "s/ /./g" | sed 's/å/a/' \
		    | sed 's/ä/a/' | sed 's/ö/o/' | sed 's/é/e/' | sed 's/è/e/' | sed 's/á/a/' | sed 's/à/a/' \
		    | sed 's/ó/o/' | sed 's/ò/o/' | sed 's/ü/u/'  | sed 's/Å/A/' \
		    | sed 's/Ä/A/' | sed 's/Ö/O/' | sed 's/É/E/' | sed 's/È/E/' | sed 's/Á/A/' | sed 's/À/A/' \
		    | sed 's/Ó/O/' | sed 's/Ò/O/' | sed 's/Ü/U/' | tr '[A-Z]' '[a-z]')
		for email_last_part in $(cat "$tempfile"); do
		    echo "${email_first_part}@${email_last_part}" >> "$dir"/found_emails.txt
		done
	    done
	fi
	rm "$tempfile"
	echo "extract_potential_email_addresses" >> "$dir"/user_searches.done
    fi
}

function extract_potential_full_names {
    if ! grep -q "^extract_potential_full_names$" "$dir"/user_searches.done; then
	echo "Extracting potential full names..."
	#echo -n "" >> "$dir"/potential_email_addresses.txt
	if grep -q -E "^first.last@|^firstname.lastname@|^first_last@|^firstname_lastname@|^etu.suku@|^etunimi.sukunimi@|^for.efter@|^fornamn.efternamn@" "$dir/found_emails.txt"; then
	    cat "$dir/found_emails.txt" | while read -r line; do
		skip=0
		if echo $line | grep -q -E "^first.last@|^firstname.lastname@|^first_last@|^firstname_lastname@|^etu.suku@|^etunimi.sukunimi@|^for.efter@|^fornamn.efternamn@"; then
		    skip=1
		elif ! echo $line | sed 's/@.*$//' | grep -q -E "\."; then
		    skip=1
		elif echo $line | grep -q -E "info.*@"; then
		    skip=1
		elif echo $line | grep -q -E "application.*@"; then
		    skip=1
		elif echo $line | grep -q -E "sales.*@"; then
		    skip=1
		elif echo $line | grep -q -E "china.*@"; then
		    skip=1
		elif [ "$(echo $line | sed 's/@.*$//' | sed 's/[^\.]//g'|tr -d '[:cntrl:]'|wc -c)" != "1" ]; then
		    skip=1
		fi
		if [ $skip -eq 0 ]; then
		    full_name=$(echo $line | sed 's/@.*$//' | sed 's/\./ /g')
		    if ! grep -q -i "$full_name" "$dir/found_full_names.txt"; then
			#echo "adding $full_name (from $line)"
			echo $full_name >> "$dir"/found_full_names.txt
		    #else
			#echo "already exists: $full_name (from $line)"
		    fi
		fi
	    done
	fi
	echo "extract_potential_full_names" >> "$dir"/user_searches.done
    fi
}

function find_emails_from_whois {
    if ! grep -q "^find_emails_from_whois$" "$dir"/user_searches.done; then
	echo "Finding email addresses from whois poc..."
	extract_found_domains
	cat "$dir"/found_domains.txt | \
	while read -r line; do
	    run_command "" "recon/contacts/gather/http/api/whois_pocs" true "-o domain=$line"
	done
	rm "$dir"/found_domains.txt
	echo "find_emails_from_whois" >> "$dir"/user_searches.done
    fi
}

function find_emails_from_pgp_search {
    if ! grep -q "^find_emails_from_pgp_search$" "$dir"/user_searches.done; then
	echo "Finding email addresses from pgp search..."
	extract_found_domains
	cat "$dir"/found_domains.txt | \
	while read -r line; do
	    run_command "" "recon/contacts/gather/http/web/pgp_search" true "-g socket_timeout=20 -o domain=$line"
	done
	rm "$dir"/found_domains.txt
	echo "find_emails_from_pgp_search" >> "$dir"/user_searches.done
    fi
}

# This one doesn't work
function find_contacts_from_jigsaw {
    if ! grep -q "^find_contacts_from_jigsaw$" "$dir"/user_searches.done; then
	echo "Finding contacts from jigsaw search..."
	company=$(echo $domain | sed 's/\..*$//')
	run_command "" "recon/contacts/gather/http/web/jigsaw" true "-o company=$company"
	echo "find_contacts_from_jigsaw" >> "$dir"/user_searches.done
    fi
}

function find_contacts_from_linkedin {
    if ! grep -q "^find_contacts_from_linkedin$" "$dir"/user_searches.done; then
	echo "Finding contacts from linkedin search..."
	company=$(echo $domain | sed 's/\..*$//')
	#run_command "" "recon/contacts/gather/http/api/linkedin_auth" true "-o company=$company"
	# Don't run this with the run_command function because the python
	# script cannot for some reason redirect the output to a file
	# ([!] 'ascii' codec can't encode character u'\xe4' in position 24: ordinal not in range(128).).
	cd /usr/local/recon-ng
	./recon-cli -w "$workspace" -m "recon/contacts/gather/http/api/linkedin_auth" -o company=$company
	cd - > /dev/null
	echo "find_contacts_from_linkedin" >> "$dir"/user_searches.done
    fi
}

function find_contacts_from_whois {
    if ! grep -q "^find_contacts_from_whois$" "$dir"/user_searches.done; then
	echo "Finding contacts from whois search..."
	#echo -n "" > "$dir"/whois_contacts.txt
	extract_host_middle_names
	for middle_name in $(cat "$dir"/hostname_middle_parts.txt); do
	    for range_start in $(grep -i $middle_name "$dir"/netrange_list.txt | cut -d' ' -f1); do
		tempfile=$(mktemp)
	        whois "$range_start" > "$tempfile"
		if [ $? -eq 0 ]; then
		    grep -E "^person:" "$tempfile" | sed 's/^[^ ]\+ \+//' | grep -v -i "internal support" \
			>> "$dir"/found_full_names.txt
		else
		    echo "Lookup failed for $range_start" >> "$dir"/run.log
		fi
		rm "$tempfile"
	    done
	done
	rm "$dir"/hostname_middle_parts.txt
	echo "find_contacts_from_whois" >> "$dir"/user_searches.done
    fi
}

function add_full_names_to_contacts {
    if ! grep -q "^add_full_names_to_contacts$" "$dir"/user_searches.done; then
	echo "Adding found full names to the contacts table..."
	cat "$dir"/found_full_names.txt | \
	while read -r line; do
	    first=$(echo $line | cut -d' ' -f1)
	    last=$(echo $line | cut -d' ' -f2-)
	    first_changed=$(echo $first | sed 's/å/a/' \
		    | sed 's/ä/a/' | sed 's/ö/o/' | sed 's/é/e/' | sed 's/è/e/' | sed 's/á/a/' | sed 's/à/a/' \
		    | sed 's/ó/o/' | sed 's/ò/o/' | sed 's/ü/u/'  | sed 's/Å/A/' \
		    | sed 's/Ä/A/' | sed 's/Ö/O/' | sed 's/É/E/' | sed 's/È/E/' | sed 's/Á/A/' | sed 's/À/A/' \
		    | sed 's/Ó/O/' | sed 's/Ò/O/' | sed 's/Ü/U/')
	    last_changed=$(echo $last | sed 's/å/a/' \
		    | sed 's/ä/a/' | sed 's/ö/o/' | sed 's/é/e/' | sed 's/è/e/' | sed 's/á/a/' | sed 's/à/a/' \
		    | sed 's/ó/o/' | sed 's/ò/o/' | sed 's/ü/u/'  | sed 's/Å/A/' \
		    | sed 's/Ä/A/' | sed 's/Ö/O/' | sed 's/É/E/' | sed 's/È/E/' | sed 's/Á/A/' | sed 's/À/A/' \
		    | sed 's/Ó/O/' | sed 's/Ò/O/' | sed 's/Ü/U/')
	    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select count(*) from contacts where (lower(fname) like lower(\"$first\") and lower(lname) like lower(\"$last\")) or (lower(fname) like lower(\"$last\") and lower(lname) like lower(\"$first\")) or (lower(fname) like lower(\"$first_changed\") and lower(lname) like lower(\"$last_changed\")) or (lower(fname) like lower(\"$last_changed\") and lower(lname) like lower(\"$first_changed\"));")
	    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    "insert into contacts (fname,lname) values (\"$first\",\"$last\");"
	    fi
	done
	echo "add_full_names_to_contacts" >> "$dir"/user_searches.done
    fi
}

function add_found_emails_to_contacts {
    if ! grep -q "^add_found_emails_to_contacts$" "$dir"/user_searches.done; then
	echo "Adding found emails to the contacts table..."
	cat "$dir"/found_emails.txt | \
	while read -r line; do
	    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select count(*) from contacts where lower(email) like lower(\"$line\");")
	    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    "insert into contacts (email) values (\"$line\");"
	    fi
	done
	echo "add_found_emails_to_contacts" >> "$dir"/user_searches.done
    fi
}

function add_found_user_names_to_contacts {
    if ! grep -q "^add_found_user_names_to_contacts$" "$dir"/user_searches.done; then
	echo "Adding found user names to the contacts table..."
	cat "$dir"/found_user_names.txt | grep -v -E "[^a-zA-Z0-9]" | \
	while read -r line; do
	    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select count(*) from contacts where lower(account_name) like lower(\"$line\");")
	    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    "insert into contacts (account_name) values (\"$line\");"
	    fi
	done
	echo "add_found_user_names_to_contacts" >> "$dir"/user_searches.done
    fi
}

function add_twitter_accounts_to_contacts {
    if ! grep -q "^add_twitter_accounts_to_contacts$" "$dir"/user_searches.done; then
	echo "Adding found twitter accounts to the contacts table..."
	cat "$dir"/found_twitter_accounts.txt | \
	while read -r line; do
	    exists=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		"select count(*) from contacts where lower(twitter_account) like lower(\"$line\");")
	    if [[ $? -eq 0 ]] && [[ "$exists" == "0" ]]; then
		sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
		    "insert into contacts (twitter_account) values (\"$line\");"
	    fi
	done
	echo "add_twitter_accounts_to_contacts" >> "$dir"/user_searches.done
    fi
}

function find_contacts {
    # Note: We could change the functions so that they all
    # add info to user_sources.txt about where the information was
    # found. Additionally they should all add the names to specific
    # stringent filenames, such as usernames.txt, emailaddresses.txt
    # and not separately for pdfs, etc. (that way it's easier to make
    # sure e.g. that extract_potential_email_addresses takes data from
    # all sources). => possibly we need to add a field sources to
    # the contacts table for this.
    find_users_from_spidered_pdfs
    find_emails_from_spidered_webpages
    find_twitter_accounts_from_spidered_webpages
    find_emails_from_whois
    find_emails_from_pgp_search
    #find_contacts_from_jigsaw
    find_contacts_from_linkedin
    find_contacts_from_whois

    # Add columns for storing found account names and twitter accounts
    # into the contacts table.
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
	"alter table contacts add column account_name text;" 2> /dev/null
    sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db \
	"alter table contacts add column twitter_account text;" 2> /dev/null

    # Add found contacts to the contacts table. Note: we could add
    # code to manually verify these before adding them to the database.
    add_found_emails_to_contacts
    add_full_names_to_contacts
    add_found_user_names_to_contacts
    add_twitter_accounts_to_contacts

    # TODO: remove the email addresses that have a domain other than the existing
    # found domains

    # TODO: change the following two functions so that they
    # take the information from the contacts table instead of from
    # some file + that they add the stuff directly to the contacts
    # table.
    extract_potential_full_names
    extract_potential_email_addresses

}

function find_extra_info {
    echo "implement this one"
    # TODO: use also the following modules:
    # namechk
    # recon/contacts/enum/http/web/dev_diver (gets info about that username from public code repositories)
    # recon/contacts/enum/http/web/should_change_password (tells which email addresses have been compromised)
    # recon/contacts/enum/http/web/haveibeenpwned (tells which users have been pwned)
    # recon/contacts/enum/http/web/pwnedlist (tells which users have been pwned)
}

if [ ! -e "$dir"/user_searches.done ]; then
    echo -n "" > "$dir"/user_searches.done
fi

#run_command "" "set domain $domain" false


nbr_contacts=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from contacts;")
find_contacts
find_extra_info
nbr_contacts_after=$(sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select count(*) from contacts;")
echo "Number of new contacts found during this run: $(($nbr_contacts_after-$nbr_contacts))" | tee -a "$dir"/run.log
if [ $nbr_contacts_after -gt $nbr_contacts ]; then
    echo "You might want to do another round." | tee -a "$dir"/run.log
fi

exit

# Make report
echo "Generating report to $dir/user_report.txt ..." | tee -a "$dir"/run.log
# list DNS servers:
if [ -e "$dir"/dns_servers.txt ]; then
    echo "DNS Servers for ${domain}:" | tee -a "$dir"/user_report.txt
    cat "$dir"/dns_servers.txt | sort | uniq | tee -a "$dir"/user_report.txt
    echo | tee -a "$dir"/user_report.txt
fi
#if [ -e "$dir"/fierce_subnets.txt ]; then
#    echo "Subnets that fierce found:" | tee -a "$dir"/user_report.txt
#    cat "$dir"/fierce_subnets.txt | tee -a "$dir"/user_report.txt
#    echo | tee -a "$dir"/user_report.txt
#fi
if [ -e "$dir"/whois_cidr_list.txt ]; then
    echo "Subnets that whois found:" | tee -a "$dir"/user_report.txt
    cat "$dir"/whois_cidr_list.txt | tee -a "$dir"/user_report.txt
    echo | tee -a "$dir"/user_report.txt
fi
# list found hosts
#run_command "Found hosts (ordered by hostname):" "query select * from hosts order by host;" true \
#    | tee -a "$dir"/user_report.txt
echo "Found hosts (ordered by hostname):" | tee -a "$dir"/run.log
sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select * from hosts order by host;" \
 | tee -a "$dir"/user_report.txt | tee -a "$dir"/run.log
echo | tee -a "$dir"/user_report.txt
#run_command "Found hosts (ordered by ip):" "query select * from hosts order by ip_address;" true \
#    | tee -a "$dir"/user_report.txt
echo "Found hosts (ordered by ip):" | tee -a "$dir"/run.log
sqlite3 ~/.recon-ng/workspaces/"$workspace"/data.db "select * from hosts order by ip_address;" \
 | tee -a "$dir"/user_report.txt | tee -a "$dir"/run.log
echo | tee -a "$dir"/user_report.txt

if [[ -f "$dir"/google_ids.txt ]] && [[ "$(cat "$dir"/google_ids.txt | wc -l)" != "0" ]]; then
    echo | tee -a "$dir"/user_report.txt
    echo "Sites having the same Google Analytics Id or same Google AdSense Id (might be" | tee -a "$dir"/user_report.txt
    echo "administrated or coded by the same people):" | tee -a "$dir"/user_report.txt
    cat "$dir"/google_ids.txt | tee -a "$dir"/user_report.txt
fi


