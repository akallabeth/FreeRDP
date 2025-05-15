#!/bin/bash -xe

RPMBUILD_BASE=~/rpmbuild/SOURCES
if [ $# -gt 0 ]; then
  RPMBUILD_BASE=$1
fi

if [ ! -d external/webview ]; then
  git clone -b navigation-listener --depth=1 https://github.com/akallabeth/webview external/webview
fi

mkdir -p "$RPMBUILD_BASE"
git rev-parse --short HEAD > $RPMBUILD_BASE/source_version
(
  cd external/webview
  git archive --format=tar --prefix=webview/ --output $RPMBUILD_BASE/webview.tar.bz2 HEAD
)

