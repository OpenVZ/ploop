#!/bin/sh

export PATH="/usr/bin:/usr/sbin:/bin:/sbin"
CRYPTSETUP=/usr/sbin/cryptsetup

loadkey()
{
	id=$(keyctl request2 user vdisk:$KEYID '' @s)
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "Cannot request the key $KEYID rc=$rc"
		exit 2
	fi

	KEY=`keyctl print "$id"`
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "Cannot read the key=$KEYID id=$id rc=$rc"
		keyctl show
		cat /proc/keys
		exit 2
	fi

	KEY=`echo "$KEY" | sed 's/^:hex://'`
}

init()
{
	loadkey
	echo -n "$KEY" | $CRYPTSETUP luksFormat $DEVICE -
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "Cannot format $DEVICE rc=$rc"
		exit 3
	fi
}

open()
{
	loadkey
	echo -n "$KEY" | $CRYPTSETUP --allow-discards luksOpen $DEVICE $DEVICE_NAME
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "Cannot open $DEVICE $DEVICE_NAME rc=$rc"
		exit 4
	fi
}

close()
{
	for ((i=0; i<60; i++)); do
		$CRYPTSETUP luksClose $DEVICE_NAME
		rc=$?
		if [ $rc -eq 0 ]; then
			exit 0
		elif [ $rc -ne 5 ]; then
			echo "Cannot close $DEVICE_NAME rc=$rc"
			exit 5
		fi
		sleep 1
	done
	exit 5
}

resize()
{
	
	$CRYPTSETUP resize $DEVICE_NAME
	if [ $? -ne 0 ]; then
		echo "Cannot resize $DEVICE_NAME"
		exit 6
	fi
}

changekey()
{
	loadkey
	CUR_KEY=$KEY
	# load new key
	KEYID=$DEVICE_NAME
	loadkey
	echo -n "${CUR_KEY}
${KEY}" | $CRYPTSETUP luksChangeKey $DEVICE -
	if [ $? -ne 0 ]; then
		echo "Cannot change key $KEYID"
		exit 7
	fi
}

case "$1" in
init)
	init
	;;
open)
	open
	;;
resize)
	resize
	;;
close)
	close
	;;
changekey)
	changekey
	;;
*)
	exit 1
esac
