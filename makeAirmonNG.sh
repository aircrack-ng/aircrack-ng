if [ -e /bin/bash ] ; then
	echo "#!/bin/bash" > airmon-ng
else
	if [ -e /bin/bash ] ; then
		echo "#!/bin/bash" > airmon-ng
	else
		echo "#!$SHELL" > airmon-ng
	fi
fi
cat airmon-ng.sh >> airmon-ng
