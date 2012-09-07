#!/bin/sh

while test -n "$1"; do
	case $1 in
	   -b|--build)
		build=yes
		;;
	   -i|--install)
		build=yes
		install=yes
		;;
	   -v|--verbose)
		verbose=yes
		;;
	   *)
		echo "Invalid argument: $1" 1>&2
		exit 1
	esac
	shift
done

RPM_SPEC=ploop.spec

# Try to figure out version from git
GIT_DESC=$(git describe --tags | sed s'/^[^0-9]*-\([0-9].*\)$/\1/')
GIT_V=$(echo $GIT_DESC | sed 's/-.*$//')
				# 3.0.28-1-gf784152
GIT_R=$(echo $GIT_DESC | sed 's/^[^-]*-\([1-9][0-9]*\)-g/\1.git./')
test "$GIT_V" = "$GIT_R" && GIT_R="1"
GIT_VR="${GIT_V}-${GIT_R}"

read_spec() {
	SPEC_V=$(awk '($1 == "Version:") {print $2}' $RPM_SPEC)
	SPEC_R=$(awk '($1 " " $2 == "%define rel") {print $3}' $RPM_SPEC)
	SPEC_VR="${SPEC_V}-${SPEC_R}"
}
read_spec

# Set version/release in spec from git
if test "$GIT_VR" != "$SPEC_VR"; then
	test -z "$verbose" || echo "Changing $RPM_SPEC:"
	# Version: 3.0.28
	# Release: 1%{?dist}
	sed -i -e "s/^\(Version:[[:space:]]*\).*\$/\1$GIT_V/" \
	       -e "s/^\(%define rel[[:space:]]*\).*\$/\1$GIT_R/" \
		$RPM_SPEC
	if test "$GIT_R" != "1"; then
		NVR='%{name}-%{version}-%{rel}'
		sed -i -e "s/^\(Source:[[:space:]]*\).*\$/\1${NVR}.tar.bz2/" \
		       -e "s/^%setup[[:space:]]*.*\$/%setup -n ${NVR}/" \
			$RPM_SPEC
	fi
fi
test -z "$verbose" || \
	grep -E -H '^Version:|^%define rel|^Source:|^%setup' $RPM_SPEC

# Set version in configure.ac from spec
read_spec
SPEC_VR=$(echo $SPEC_VR | sed 's/-1$//')

test "$build" = "yes" || exit 0
make rpms || exit 1

test "$install" = "yes" || exit 0
sudo rpm -Uhv $(rpm --eval %{_rpmdir}/%{_arch})/ploop-*${GIT_VR}*.rpm
