#!/bin/bash
# Copyright (c) 2013 Peter Kiss
# Copyright (c) 2012 Michael Nowack
# Copyright (c) 2010, 2012 Yu-Jie Lin
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

FLICKROAUTH_VERSION=1.0

# Flickr API endpoints

F_REQUEST_TOKEN='http://www.flickr.com/services/oauth/request_token'
F_ACCESS_TOKEN='http://www.flickr.com/services/oauth/access_token'
F_AUTHORIZE_TOKEN='http://www.flickr.com/services/oauth/authorize'

F_API_ENDPOINT='http://ycpi.api.flickr.com/services/rest'

# Source OAuth.sh

OAuth_sh=$(which OAuth.sh)
(( $? != 0 )) && echo 'Unable to locate OAuth.sh! Make sure it is in searching PATH.' && exit 1
source "$OAuth_sh"

FO_debug () {
  # Print out all parameters, each in own line
  [[ "$FO_DEBUG" == "" ]] && return
  local t=$(date +%FT%T.%N)
  while (( $# > 0 )); do
    echo "[TO][DEBUG][$t] $1"
    shift 1
    done
  }

FO_extract_value () {
  # $1 key name
  # $2 string to find
  egrep -o "$1=[a-zA-Z0-9-]*" <<< "$2" | cut -d\= -f 2
  }


FO_init() {
  # Initialize OAuth
  oauth_version='1.0'
  oauth_signature_method='HMAC-SHA1'
  oauth_basic_params=(
    $(OAuth_param 'oauth_consumer_key' "$oauth_consumer_key")
    $(OAuth_param 'oauth_signature_method' "$oauth_signature_method")
    $(OAuth_param 'oauth_version' "$oauth_version")
    )
  }

FO_access_token_helper () {
  # Help guide user to get access token

  local resp PIN

  # Request Token
  
  local auth_header="$(_OAuth_authorization_header 'Authorization' $F_API_ENDPOINT "$oauth_consumer_key" "$oauth_consumer_secret" '' '' "$oauth_signature_method" "$oauth_version" "$(OAuth_nonce)" "$(OAuth_timestamp)" 'POST' "$F_REQUEST_TOKEN" "$(OAuth_param 'oauth_callback' 'oob')"), $(OAuth_param_quote 'oauth_callback' 'oob')"
  
  resp=$(curl -s -d '' -H "$auth_header" "$F_REQUEST_TOKEN")
  FO_rval=$?
  (( $? != 0 )) && return $FO_rval

  local _oauth_token=$(FO_extract_value 'oauth_token' "$resp")
  local _oauth_token_secret=$(FO_extract_value 'oauth_token_secret' "$resp")

  echo 'Please go to the following link to get the PIN:'
  echo "  ${F_AUTHORIZE_TOKEN}?oauth_token=$_oauth_token"
  
  read -p 'PIN: ' PIN

  # Access Token

  local auth_header="$(_OAuth_authorization_header 'Authorization' $F_API_ENDPOINT "$oauth_consumer_key" "$oauth_consumer_secret" "$_oauth_token" "$_oauth_token_secret" "$oauth_signature_method" "$oauth_version" "$(OAuth_nonce)" "$(OAuth_timestamp)" 'POST' "$F_ACCESS_TOKEN" "$(OAuth_param 'oauth_verifier' "$PIN")"), $(OAuth_param_quote 'oauth_verifier' "$PIN")"

  resp=$(curl -s -d "" -H "$auth_header" "$F_ACCESS_TOKEN")
  FO_rval=$?
  (( $? != 0 )) && return $FO_rval
  
  FO_ret=(
    $(FO_extract_value 'oauth_token' "$resp")
    $(FO_extract_value 'oauth_token_secret' "$resp")
    )

  oauth_token=${FO_ret[0]}
  oauth_token_secret=${FO_ret[1]}
  }

# APIs
######

FO_getUploadStatus () {
  # flickr.people.getUploadStatus
  local params=(
    $(OAuth_param 'method' "flickr.people.getUploadStatus")
    $(OAuth_param 'api_key' "$1")
    $(OAuth_param 'oauth_token' "$2")
  )
	local auth_header=$(OAuth_authorization_header 'Authorization' "$F_API_ENDPOINT" '' '' 'GET' "$F_API_ENDPOINT" ${params[@]})

	FO_ret=$(curl -s -H "$auth_header" "$F_API_ENDPOINT?$(OAuth_params_string ${params[@]})")
	FO_rval=$?
	
	return $FO_rval
	}

FO_checkToken () {
  # flickr.auth.oauth.checkToken
  local params=(
    $(OAuth_param 'method' "flickr.auth.oauth.checkToken")
    $(OAuth_param 'api_key' "$1")
    $(OAuth_param 'oauth_token' "$2")
  )
	local auth_header=$(OAuth_authorization_header 'Authorization' "$F_API_ENDPOINT" '' '' 'GET' "$F_API_ENDPOINT" ${params[@]})

	FO_ret=$(curl -s -H "$auth_header" "$F_API_ENDPOINT?$(OAuth_params_string ${params[@]})")
	FO_rval=$?
	
	return $FO_rval
	}
