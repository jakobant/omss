#!/bin/bash

if [ "$#" -eq 0 ]
then
    echo "I need arguments ... NessusHostDiff.py NessusScans.py NessusToSql.py"
    exit 1
fi

echo $@

python $@


