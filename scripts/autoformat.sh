#!/bin/bash
MY_PATH="`dirname \"$0\"`"              # relative
MY_PATH="`( cd \"$MY_PATH\" && pwd )`"  # absolutized and normalized
CHANGESET=`git status | cut -d ':' -f 2 | grep -vE "#|no" | grep -E "*\.h|*\.c"` # get filenames from git status

CHANGESET=$(find . -iname "*\.[c.h.m]")
$MY_PATH/format_code.sh $CHANGESET
