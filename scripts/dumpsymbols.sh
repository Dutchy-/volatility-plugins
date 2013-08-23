#!/bin/sh
set -x
FILE=$1
DUMPDIR=$2

REALFILE=`readlink -f $FILE`
BASE=`basename $REALFILE`

nm "$FILE" > "$DUMPDIR/$BASE.symbols"
nm -D "$FILE" > "$DUMPDIR/$BASE.dynsym"
