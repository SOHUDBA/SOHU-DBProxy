#!/bin/bash
echo "=== $0: upload to delivery server ==="
CURL='curl --user xxx@xxxxx --verbose --ftp-create-dirs --upload-file'
LATEST_BUILD_TAG=latest_build_tag
LATEST_BUILD_TAG_STRING="${BUILD_ID}-${BUILD_NUMBER}-${SVN_REVISION}"

__no__use___upload()
{
  declare -r _file=$1
  declare -r _dest=$2
  $CURL ${PACKAGE}-${_file}.tar.gz $URL_PREFIX/${_dest}/${PACKAGE}-${_file}.tar.gz
}
upload()
{
  declare -r _file=$1
  declare -r _dest=$2
  $CURL ${PACKAGE}-${_file}.${OS_RELEASE}.tar.gz $URL_PREFIX/${_dest}/${PACKAGE}-${_file}.${OS_RELEASE}.tar.gz
}
upload_tag()
{
  declare -r _dest=$1
  echo "${LATEST_BUILD_TAG_STRING}" >./${LATEST_BUILD_TAG}
  $CURL ./${LATEST_BUILD_TAG} $URL_PREFIX/${_dest}/${LATEST_BUILD_TAG}.${OS_RELEASE}
}

source ./build_setenv.sh && \
URL_PREFIX="ftp://x.x.x.x/MySQL/Proxy/dbproxy/build/${PACKAGE_VERSION}" && \
PACKAGE=${PACKAGE_NAME}-${PACKAGE_VERSION} && \
(
upload "src" "${LATEST_BUILD_TAG_STRING}" && \
upload "bin" "${LATEST_BUILD_TAG_STRING}" && \
upload "src" "latest" && \
upload "bin" "latest" && \
upload_tag "${LATEST_BUILD_TAG_STRING}" && \
upload_tag "latest"
)

#eof
