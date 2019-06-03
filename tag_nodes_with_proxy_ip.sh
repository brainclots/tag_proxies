#!/bin/bash

# Script to tag all nodes with proxy IP
# Assumptions:
#   1. A rule exists to gather the proxy IP in use from the agent config file (storing in an element named 'proxy_ip')
#   2. A Tag Set named "Proxy Host" exists, containing a tag for each proxy IP a node can connect through.
#   3. There is a TECommander auth file for the console in question, that is accessible from where the rule is to be
#      run (where TECommander is installed)

[[ -z "$1" ]] && { echo -e "\n   Usage: $0 auth_files/<customer>_auth.xml \n   Supply the path to an auth file for the customer's console.\n" ; exit 1; }

if [[ -e "$1" ]] ; then
	AUTH=$1
else
	echo "$1" does not exist!
	exit
fi

TECMDR=/usr/local/tripwire/te/tecommander/bin/tecommander.sh

# First, create a report from the desired console with the nodes that have a 'proxy_ip' element

echo -e "\n    Running report of nodes with proxy_ip element...\n"
$TECMDR report \
	-T "Which Proxy for each node" \
	-t elementcontents_rpt \
	-P "BooleanCriterion,currentVersionsOnly,true:MatchCriterion,elementName,equals,proxy_ip:SelectCriterion,elementExists,Yes,yes" \
	-F xml \
	-o proxy-${SUDO_USER}.xml \
	-M $AUTH \
	-Q

# Next, use the report to create an input file for TECommander
> tags-${SUDO_USER}.txt
IFS=" " read -r -a INFO <<< $(sed -n proxy-${SUDO_USER}.xml -e '/String name=\(\"node\"\|\"content\"\)/p' | sed -ne 's/^.*>\(.*\)<.*/\1/p')
for (( i=0; i<${#INFO[@]} ; i+=2 )) ; do
        echo avtagasset -n ${INFO[i]} -S \"Proxy Host\" -T ${INFO[i+1]} -M $AUTH -Q >> tags-${SUDO_USER}.txt
done

echo Verify the data in tags-${SUDO_USER}.txt, then pass it to tecommander like so:

echo "    tecommander.sh @tags-${SUDO_USER}.txt"
