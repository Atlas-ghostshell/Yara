#!/bin/bash

# Get current working directory and log file
LOCAL=$(dirname $0)
cd $LOCAL
cd ../
PWD=$(pwd)
LOG_FILE="${PWD}/../logs/active-responses.log"

# Read input from Wazuh
read INPUT_JSON
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)
COMMAND=$(echo "$INPUT_JSON" | jq -r .command)

# Only proceed if command is "add"
if [[ "$COMMAND" == "add" ]]; then
  printf '{"version":1,"origin":{"name":"yara-threat","module":"active-response"},"command":"check_keys","parameters":{"keys":[]}}\n'
  read RESPONSE
  COMMAND2=$(echo "$RESPONSE" | jq -r .command)

  if [[ "$COMMAND2" != "continue" ]]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') remove-threat: Aborted for $FILENAME" >> $LOG_FILE
    exit 0
  fi
fi

# Run YARA and check if it matches
MATCH=$(yara /var/ossec/rules/malware_rules.yar "$FILENAME" 2>/dev/null)

if [[ -n "$MATCH" ]]; then
  rm -f "$FILENAME"
  if [[ $? -eq 0 ]]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') remove-threat: Deleted malicious file $FILENAME (YARA match)" >> $LOG_FILE
  else
    echo "$(date '+%Y/%m/%d %H:%M:%S') remove-threat: Error deleting $FILENAME" >> $LOG_FILE
  fi
else
  echo "$(date '+%Y/%m/%d %H:%M:%S') remove-threat: YARA found no match in $FILENAME. File retained." >> $LOG_FILE
fi

exit 0
