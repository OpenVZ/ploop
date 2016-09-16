#!/bin/sh

export PATH="/usr/bin:/usr/sbin:/bin:/sbin"
CRYPTSETUP=/usr/sbin/cryptsetup

loadkey()
{
	local id=$(keyctl request2 user vdisk:$KEYID '' @u)
	[ -z "$id" ] && exit 2
	KEY=`keyctl print $id | sed 's/^:hex://'`
}

init()
{
	loadkey
	echo -n "$KEY" | $CRYPTSETUP luksFormat $DEVICE -
	if [ $? -ne 0 ]; then
		echo "Cannot format $DEVICE"
		exit 3
	fi
}

open()
{
	loadkey
	echo -n "$KEY" | $CRYPTSETUP --allow-discards luksOpen $DEVICE $DEVICE_NAME
	if [ $? -ne 0 ]; then
		echo "Cannot open $DEVICE $DEVICE_NAME"
		exit 4
	fi
}

close()
{
	for ((i=0; i<60; i++)); do
		$CRYPTSETUP luksClose $DEVICE_NAME
		if [ $? -eq 0 ]; then
			break
		elif [ $? -ne 5 ]; then
			echo "Cannot close $DEVICE_NAME"
			exit 5
		fi
		sleep 1
	done
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
