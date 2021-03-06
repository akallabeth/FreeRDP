#!/bin/bash

ASTYLE=$(which astyle)

if [ ! -x $ASTYLE ]; then
  echo "No astyle found in path, please install."
  exit 1
fi

# Need at least astyle 2.03 due to bugs in older versions
# indenting headers with extern "C"
STR_VERSION=$($ASTYLE --version 2>&1)
VERSION=$(echo $STR_VERSION | cut -d ' ' -f4)
MAJOR_VERSION=$(echo $VERSION | cut -d'.' -f1)
MINOR_VERSION=$(echo $VERSION | cut -d'.' -f2)
echo $STR_VERSION

if [ "$MAJOR_VERSION" -lt "2" ]; then
  echo "Your version of astyle($VERSION) is too old, need at least 2.03"
  exit 1
fi

if [ "$MINOR_VERSION" -lt "3" ]; then
  echo "Your version of astyle($VERSION) is too old, need at least 2.03"
  exit 1
fi

if [ $# -le 0 ]; then
  echo "Usage:"
  echo -e "\t$0 <file1> [<file2> ...]"
  exit 2
fi

$ASTYLE --lineend=linux --mode=c --indent=force-tab=4 --brackets=linux --pad-header \
	--indent-switches --indent-cases --indent-preprocessor \
	--indent-col1-comments --break-closing-brackets \
	--align-pointer=type --indent-labels --brackets=break \
	--unpad-paren --break-blocks $@
exit $?
