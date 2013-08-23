#!/bin/sh

DIR=$1
DUMPDIR=$2

SO=`find $DIR -type f -name "*.so"`

for FILE in $SO; do
    ./dumpsymbols.sh "$FILE" "$DUMPDIR"
done
