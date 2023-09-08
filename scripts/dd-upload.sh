  #!/usr/bin/env sh

  # this shell script is meant to be executed by a Aquasec/Postee "exec"
  # action, the event data is passed in through environment variable
  # POSTEE_EVENT
  #
  # Requirements on JSON format
  # ---------------------------
  # - JSON dictionary with "defectdojo" as top-level key
  # - "defectdojo" dictionary holds at least 2 keys
  #   - "scan", containing the report
  #   - "metadata", containing key/value pairs
  #
  # Required parameter
  # ------------------
  # - DEFECTDOJO_URL - Defectdojo URL, base URL, script appends path for v2
  # - DEFECTDOJO_API_TOKEN
  # - POSTEE_EVENT - variable containing the JSON content from template stage


  TEMP_PREFIX="/tmp/dd-scan-"

  if [ -z "$DEFECTDOJO_API_TOKEN" ]; then
    echo "ERROR: could not find environment variable DEFECTDOJO_API_TOKEN"
    exit 1
  fi

  if [ -z "$DEFECTDOJO_URL" ]; then
    echo "could not find environment variable DEFECTDOJO_URL" 
    exit 1
  fi

  if [ -z "$POSTEE_EVENT" ]; then
    echo "could not read any input data from POSTEE_EVENT"
    exit 1
  fi

  # shellcheck disable=SC2317 # used in signal trap for EXIT
  _cleanup() {
    rm -f "${TEMP_PREFIX}*"
  }

  trap _cleanup EXIT

  # write a temporary file with content received from POSTEE_EVENT
  TMP_FILE="$(mktemp ${TEMP_PREFIX}XXXXXX)"

  _validate_json()
  {
    if echo "$POSTEE_EVENT" | jq '.defectdojo.scan' | grep 'null' 1>/dev/null; then
      echo "ERROR => JSON, unexpected structure \"defectdojo\""
      return 1
    fi
  }
  if ! _validate_json; then
    exit 1
  fi

  echo "$POSTEE_EVENT" | jq '.defectdojo.scan' | tee "$TMP_FILE"

  # Initialize the command string
  COMMAND="curl -H \"Authorization: Token $DEFECTDOJO_API_TOKEN\""

  # Check verb (action) to be performed, based on .defectdojo.verb
  VERB=$(echo "$POSTEE_EVENT" | jq '.defectdojo.verb')

  # If verb is delete, call DELETE on /api/v2/tests with the test_title, else call POST on /api/v2/reimport-scan/
  if [ "$VERB" = "delete" ]; then
    # extract test_title from metadata key
    TEST_TITLE=$(echo "$POSTEE_EVENT" | jq '.defectdojo.metadata.test_title')
    echo "INFO: verb is delete, will delete test with title ${TEST_TITLE}"
    if [ -z "$TEST_TITLE" ]; then
      echo "ERROR: could not find test_title in metadata"
      exit 1
    else
      DD_DELETE_URL="${DEFECTDOJO_URL}/api/v2/tests/?title=${TEST_TITLE}"
      COMMAND="$COMMAND -X DELETE ${DD_DELETE_URL}"
    fi
  else
    echo "Import new scan"
    # extract all key/value pairs from metadata key
    # convert the resulting dictionary into multiline
    # string => $key=$value, can further be consumed
    # in a FOR loop generating a FORM entry per row
    FORM_ENTRIES=$(echo "$POSTEE_EVENT" | jq '.defectdojo.metadata | keys_unsorted[] as $k | "\($k)=\( .[$k])"')

    # to be able to ignore whitespaces in values,
    # separator for FOR loops is configured to
    # a newline character, remove unset IFS
    OLD_IFS="$IFS"
    # shellcheck disable=SC3003
    IFS=$'\n'
    for entry in $FORM_ENTRIES; do
      COMMAND="$COMMAND -F $entry"
    done
    IFS="$OLD_IFS"


    DD_IMPORT_URL="${DEFECTDOJO_URL}/api/v2/reimport-scan/"

    # add URL and final JSON payload (trivy report)
    COMMAND="$COMMAND -F \"file=@${TMP_FILE}\" -X POST ${DD_IMPORT_URL}"
  fi

  echo "Command: $COMMAND"
  if ! eval "$COMMAND"; then
    echo "ERROR: failed to call ${DD_IMPORT_URL}"
    exit 1
  fi

  echo "SUCCESS: status ok from ${DD_IMPORT_URL}"
  exit 0