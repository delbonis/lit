#!/bin/bash

fail=0
bad=''

for td in */; do
	if [ "$td" == "build/" ]; then
		continue
	fi
	if [ "$td" == "cmd/" ]; then
		continue
	fi

	gocnt=$(ls $td | grep -E '\.go$' | wc -l)
	if [ $gocnt -gt 0 ]; then
		echo "Running go test in $td"
		go test -v ./$td
		res=$?
		if [ "$res" -ne "0" ]; then
			fail=1
			bad="$bad $td"
		fi
		echo ''
	fi
done

if [ "$fail" -eq 1 ]; then
	echo 'Failed:' $bad
	exit 1
fi
