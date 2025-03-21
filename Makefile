.PHONY: all clean

all:
	bash build.sh

clean:
	rm -f seccomp-error seccomp-strict seccomp-init
