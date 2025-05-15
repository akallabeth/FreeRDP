#!/bin/bash -xe
#
# Create a RPM package
SCRIPT_PATH=$(dirname "${BASH_SOURCE[0]}")
SCRIPT_PATH=$(realpath "$SCRIPT_PATH")

RPMBUILD_BASE=~/rpmbuild/SOURCES
if [ $# -gt 0 ]; then
  RPMBUILD_BASE=$1
fi

mkdir -p $RPMBUILD_BASE
($SCRIPT_PATH/prepare_rpm_freerdp-nightly.sh $(pwd))

git archive --format=tar --prefix=freerdp-nightly-3.0/ --output $RPMBUILD_BASE/freerdp-nightly-3.0.tar.bz2 HEAD
cp webview.tar.bz2 $RPMBUILD_BASE/
cp source_version $RPMBUILD_BASE/
rpmbuild -bs "$SCRIPT_PATH/../rpm/freerdp-nightly.spec"
rpmbuild -bb "$SCRIPT_PATH/../rpm/freerdp-nightly.spec"
