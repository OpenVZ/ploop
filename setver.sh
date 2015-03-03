#!/bin/sh

OPTS=$(getopt -o biUFvo --long \
	build,install,update,freshen,verbose,oldpackage \
	-n 'setver.sh' -- "$@")

eval set -- "$OPTS"

while true; do
	case $1 in
	   -b|--build)
		build=yes
		;;
	   -i|--install)
		build=yes
		install=i
		;;
	   -U|--update)
		build=yes
		install=U
		;;
	   -F|--freshen)
		build=yes
		install=F
		;;
	   -v|--verbose)
		verbose=yes
		;;
	   -o|--oldpackage)
		rpm_install_flags="${rpm_install_flags} --oldpackage"
		;;
	   --)
		break
		;;
	   *)
		echo "Invalid argument: $1" 1>&2
		exit 1
	esac
	shift
done

test "$build" = "yes" && clean="yes"

NAME=ploop
RPM_SPEC=${NAME}.spec
MAKEFILE=Makefile.inc

# Try to figure out version from git
GIT_DESC=$(git describe --tags | sed s'/^[^0-9]*-\([0-9].*\)$/\1/')
			# 3.0.28-1-gf784152
GIT_V=$(echo $GIT_DESC | awk -F - '{print $1}')
GIT_R=$(echo $GIT_DESC | awk -F - '{print $2}')
GIT_T=$(echo $GIT_DESC | awk -F - '{print $3}')
test "x$GIT_R" = "x" && GIT_R="1"
GIT_VR="${GIT_V}-${GIT_R}"

BUILDID=$(cat .build-id 2>/dev/null || echo 0)
if test "${GIT_VR}" = "$(cat .version-id 2>/dev/null)"; then
	BUILDID=$((BUILDID+1))
	GIT_R="${GIT_R}.${BUILDID}"
else
	echo "${GIT_VR}" > .version-id
	BUILDID=0
fi
echo "${BUILDID}" > .build-id

GIT_RT="${GIT_R}.${GIT_T}"
test "x$GIT_T" = "x" && GIT_RT="${GIT_R}"
GIT_VRT="${GIT_V}-${GIT_RT}"

read_spec() {
	SPEC_V=$(awk '($1 == "Version:") {print $2}' $RPM_SPEC)
	SPEC_R=$(awk '($1 " " $2 == "%define rel") {print $3}' $RPM_SPEC)
	SPEC_VR="${SPEC_V}-${SPEC_R}"
}
read_spec

# Store original spec
if test "$clean" = "yes"; then
	cp -a $RPM_SPEC .$RPM_SPEC.$$
	ATEXIT="mv -f .$RPM_SPEC.$$ $RPM_SPEC"
	trap "$ATEXIT" EXIT
fi

# Set version/release in spec from git
if test "$GIT_VR" != "$SPEC_VR"; then
	test -z "$verbose" || echo "Changing $RPM_SPEC:"
	# Version: 3.0.28
	# Release: 1%{?dist}
	sed -i -e "s/^\(Version:[[:space:]]*\).*\$/\1$GIT_V/" \
	       -e "s/^\(%define rel[[:space:]]*\).*\$/\1$GIT_RT/" \
		$RPM_SPEC
	if test -n "$GIT_T"; then
		NVR='%{name}-%{version}-%{rel}'
		sed -i -e "s/^\(Source:[[:space:]]*\).*\$/\1${NVR}.tar.bz2/" \
		       -e "s/^%setup[[:space:]]*.*\$/%setup -n ${NVR}/" \
			$RPM_SPEC
	fi
fi
test -z "$verbose" || \
	grep -E -H '^Version:|^%define rel|^Source:|^%setup' $RPM_SPEC

# Store original Makefile
if test "$clean" = "yes"; then
	cp -a $MAKEFILE .$MAKEFILE.$$
	ATEXIT="$ATEXIT; mv -f .$MAKEFILE.$$ $MAKEFILE"
	trap "$ATEXIT" EXIT
fi

# Set version in Makefile from git
MF_V=$(awk -F = '($1 == "VERSION") { print $2; }' $MAKEFILE)
MF_R=$(awk -F = '($1 == "RELEASE") { print $2; }' $MAKEFILE)
GIT_R_MF="-$GIT_RT"
test "$GIT_RT" = "1" && GIT_R_MF=""
if test "$GIT_V" != "$MF_V" -o "$GIT_R_MF" != "MF_R"; then
	test -z "$verbose" || echo "Changing $MAKEFILE:"
	# VERSION=1.12
	# RELEASE=
	sed -i -e "s/^\(VERSION=\).*\$/\1$GIT_V/" \
	       -e "s/^\(RELEASE=\).*\$/\1$GIT_R_MF/" \
		$MAKEFILE
fi

test -z "$verbose" || \
	grep -E -H "^VERSION=|^RELEASE=" $MAKEFILE

test "$build" = "yes" || exit 0
make rpms || exit 1

# Remove dist tarball
test "$clean" = "yes" && rm -f ${NAME}-${GIT_VRT}.tar.bz2

test -z "$install" && exit 0
sudo rpm -${install}hv ${rpm_install_flags} \
	$(rpm --eval %{_rpmdir}/%{_arch})/${NAME}-*${GIT_VRT}*.rpm || exit 1

# Remove rpms
if test "$clean" = "yes"; then
	rm -f $(rpm --eval %{_rpmdir}/%{_arch})/${NAME}-*${GIT_VRT}*.rpm
	rm -f $(rpm --eval %{_srcrpmdir})/${NAME}-*${GIT_VRT}*.src.rpm
fi
