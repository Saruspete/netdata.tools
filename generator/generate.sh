#!/usr/bin/env bash

typeset MYSELF="$(readlink -e $0 || realpath $0)"
typeset MYPATH="${MYSELF%/*}"

#set -o nounset -o noclobber
#export LC_ALL=C
#export PATH="/bin:/sbin:/usr/bin:/usr/sbin:$PATH"
#export PS4=' (${BASH_SOURCE##*/}:$LINENO ${FUNCNAME[0]:-main})  '

# Load main library
typeset -a ammpaths=("$MYPATH/ammlib" "$HOME/.ammlib" "/etc/ammlib")
for ammpath in "${ammpaths[@]}" fail; do
	[[ -e "$ammpath/ammlib" ]] && source "$ammpath/ammlib" && break
done
if [[ "$ammpath" == "fail" ]]; then
	echo >&2 "Unable to find ammlib in paths '${ammpaths[@]}'"
	echo >&2 "Download it with 'git clone https://github.com/Saruspete/ammlib.git $MYPATH'"
	exit 1
fi

# Load the required libraries
ammLib::Require "optparse" "http" "string"

typeset CG_VERSION="latest"
typeset CG_GITHUB="swagger-api/swagger-codegen"
typeset CG_DEST="$MYPATH/swagger-codegen"
#typeset CG_ASSET_BASE="https://repo1.maven.org/maven2/io/swagger/swagger-codegen-cli"
typeset CG_ASSET_BASE="https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli"

typeset JAVA_PATH="$(ammExec::GetPath "java")"

typeset ND_SWAGGER="http://127.0.0.1:19999/netdata-swagger.json"
typeset ND_LANG="python"
typeset ND_DEST="$(readlink -f "$MYPATH/../api")"

ammOptparse::AddOptGroup "codegen" "Codegen Details"
ammOptparse::AddOpt "-r|--release=" "Codegen release"           "$CG_VERSION"
ammOptparse::AddOpt "-g|--github="  "Codegen github path"       "$CG_GITHUB"
ammOptparse::AddOpt "-c|--cgdest="  "Codegen destination path"  "$CG_DEST"

ammOptparse::AddOptGroup "java" "Java details"
ammOptparse::AddOpt "-j|--java="    "Path to java executable"   "$JAVA_PATH"

ammOptparse::AddOptGroup "netdata" "Netdata API details"
ammOptparse::AddOpt "-s|--swagger=" "Path to netdata swagger.json" "$ND_SWAGGER"
ammOptparse::AddOpt "-l|--lang="    "Lang to translate API to"     "$ND_LANG"
ammOptparse::AddOpt "-a|--apidest=" "Path to API files output"     "$ND_DEST"


ammOptparse::Parse || ammLog::Die "Parsing error. Please check"
eval set -- $(ammOptparse::GetUnparsedOpts)


CG_VERSION="$(ammOptparse::Get "release")"
CG_GITHUB="$(ammOptparse::Get "github")"
CG_DEST="$(ammOptparse::Get "cgdest")"

JAVA_PATH="$(ammOptparse::Get "java")"

ND_SWAGGER="$(ammOptparse::Get "swagger")"
ND_LANG="$(ammOptparse::Get "lang")"
ND_DEST="$(ammOptparse::Get "apidest")"


if [[ "$CG_VERSION" == "latest" ]]; then
	CG_VERSION="$(ammHttp::GithubReleaseGetLastVersion "$CG_GITHUB")"
fi


# Create storage folders
[[ -d "$CG_DEST" ]] || mkdir -p "$CG_DEST"
[[ -d "$ND_DEST" ]] || mkdir -p "$ND_DEST"

# Ensure we have the codegen available
typeset asset="$CG_ASSET_BASE/${CG_VERSION#v}/swagger-codegen-cli-${CG_VERSION#v}.jar"
typeset jardst="$CG_DEST/${asset##*/}"

if ! [[ -s "$jardst" ]]; then
	# Download it
	if ! ammHttp::FetchSmart "$asset" "$jardst" >/dev/null 2>&1; then
		ammLog::Error "Cannot fetch version '$CG_VERSION' from url '$asset' to '$jardst'"
		exit 1
	fi
fi

# Copy source json to local file
#if ammString::IsUrl "$ND_SWAGGER"; then
#	typeset swaggerjson="$(ammHttp::FetchSmart "$ND_SWAGGER" "$ND_DEST/${ND_SWAGGER##*/}")"
#	if [[ -z "$swaggerjson" ]] || ! [[ -s "$swaggerjson" ]]; then
#		ammLog::Error "Unable to copy swagger.json '$ND_SWAGGER' to '$ND_DEST'"
#		exit 2
#	fi
#
#	ND_SWAGGER="$swaggerjson"
#fi


# Execute
ammLog::Info "Executing: $JAVA_PATH -jar '$jardst' generate -l '$ND_LANG' -i '$ND_SWAGGER' -o '$ND_DEST/api.py' $@"
$JAVA_PATH -jar "$jardst" generate --lang "$ND_LANG" --input-spec "$ND_SWAGGER" --output "$ND_DEST/" "$@"
