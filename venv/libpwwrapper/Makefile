.PHONY: test all clean

all: libpwwrapper.so libpwwrapper32.so

libpwwrapper.so: libpwwrapper.c
	$(CC) -fPIC -O3 -shared -o $@ $< -ldl

libpwwrapper32.so: libpwwrapper.c
	$(CC) -m32 -fPIC -O3 -shared -o $@ $< -ldl

clean:
	rm -f libpwwrapper32.so libpwwrapper.so

test: libpwwrapper.so
	@echo "Normal behavior:"; \
		export HOME=_FAKE_$$HOME; python -c "import pwd; print pwd.getpwuid($(shell id -u)).pw_dir"; \
		echo "With our wrapper:"; \
		RESULT=`LD_PRELOAD=./libpwwrapper.so python -c "import pwd; print pwd.getpwuid($(shell id -u)).pw_dir"`; \
		echo $$RESULT; echo "--------------------------"; \
		if [ "$$RESULT" = "$$HOME" ]; then echo "pass"; else echo "Fail"; fi
