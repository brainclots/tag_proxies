#!/bin/bash

# Script to tag all nodes with proxy IP
# Assumptions:
#   1. A rule exists to gather the proxy IP in use from the agent config file (storing in an element named 'proxy_ip')
#   2. A Tag Set named "Proxy Host" exists.
#   3. There is a TECommander auth file for the console in question, that is accessible from where the script is to be
#      run (where TECommander is installed)

[[ -z "$1" ]] && { echo -e "\n   Usage: $0 auth_files/<customer>_auth.xml \n   Supply the path to an auth file for the customer's console.\n" ; exit 1; }

if [[ -e "$1" ]] ; then
	AUTH=$1
else
	echo "$1" does not exist!
	exit
fi

TECMDR=/usr/local/tripwire/te/tecommander/bin/tecommander.sh
CUSTOMER=$(echo $1 | sed -e 's/.*auth_files\/\(.*\)_auth.xml/\1/')

# First, create a report from the desired console with the nodes that have a 'proxy_ip' element

echo -e "\n    Running report of nodes with proxy_ip element on the $CUSTOMER console...\n"
$TECMDR report \
	-T "Which Proxy for each node" \
	-t elementcontents_rpt \
	-P "BooleanCriterion,currentVersionsOnly,true:MatchCriterion,elementName,equals,proxy_ip:SelectCriterion,elementExists,Yes,yes" \
	-F xml \
	-w "No Proxy Tagged" \
	-o /tmp/proxy-${CUSTOMER}.xml \
	-M $AUTH \
	-Q -q

# See if report was created successfully
[[ ! -e /tmp/proxy-${CUSTOMER}.xml ]] && { echo "Report not created. Troubleshoot TECommander output." ; exit 1; }

# Now, check to see that the tagset and tags required exist in the console.
PROXY_IPS=$(sed -n /tmp/proxy-${CUSTOMER}.xml -e '/String name=\(\"content\"\)/p' | sed -ne 's/^.*>\(.*\)<.*/\1/p' | sed '/^$/d' | sort | uniq)
echo Creating tags for each proxy identified...
> proxy-tags-${CUSTOMER}.txt
for PROXY in $PROXY_IPS ; do
	echo avcreatetag -S \"Proxy Host\" -T $PROXY -M $AUTH -Q -q >> proxy-tags-${CUSTOMER}.txt
done
$TECMDR @proxy-tags-${CUSTOMER}.txt
rm -f proxy-tags-${CUSTOMER}.txt

# Next, use the report to create an input file for TECommander
> /tmp/tags-${CUSTOMER}.txt
IFS=" " read -r -a INFO <<< $(sed -n /tmp/proxy-${CUSTOMER}.xml -e '/String name=\(\"node\"\|\"content\"\)/p' | sed -ne 's/^.*>\(.*\)<.*/\1/p')
for (( i=0; i<${#INFO[@]} ; i+=2 )) ; do
        echo avtagasset -n ${INFO[i]} -S \"Proxy Host\" -T ${INFO[i+1]} -M $AUTH -Q >> /tmp/tags-${CUSTOMER}.txt
done

echo Verify the data in /tmp/tags-${CUSTOMER}.txt, then pass it to tecommander like so:

echo "    tecommander.sh @/tmp/tags-${CUSTOMER}.txt"
