/*
 * Wrapper for getpw* functions
 *
 * Cite from the GLib documentation:
 *
 *   Note that in contrast to traditional UNIX tools, this function prefers
 *   passwd entries over the HOME environment variable.  One of the reasons for
 *   this decision is that applications in many cases need special handling to
 *   deal with the case where HOME is
 *
 * ..which should make clear why this is required in a sandbox. This library
 * also changes the getpw* functions to make sure other programs with this
 * misbehavior are also covered.
 *
 */

#define __USE_GNU
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <dlfcn.h>

const char *g_get_home_dir(void) {
	return getenv("HOME");
}

struct passwd *getpwent(void) {
	struct passwd *retval = ((struct passwd*(*)(void))(dlsym(RTLD_NEXT, "getpwent")))();
	if(retval != NULL) {
		retval->pw_dir = getenv("HOME");
	}
	return retval;
}

struct passwd *getpwnam(const char *name) {
	struct passwd *retval = ((struct passwd*(*)(const char *))(dlsym(RTLD_NEXT, "getpwnam")))(name);
	if(retval != NULL) {
		retval->pw_dir = getenv("HOME");
	}
	return retval;
}

struct passwd *getpwuid(uid_t uid) {
	struct passwd *retval = ((struct passwd*(*)(uid_t))(dlsym(RTLD_NEXT, "getpwuid")))(uid);
	if(retval != NULL) {
		retval->pw_dir = getenv("HOME");
	}
	return retval;
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
	int retval = ((int (*)(const char *, struct passwd *, char *, size_t, struct passwd **))(dlsym(RTLD_NEXT, "getpwnam_r")))(name, pwd, buf, buflen, result);
	if(retval != 0) {
		(*result)->pw_dir = getenv("HOME");
	}
	return retval;
}

int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
	int retval = ((int (*)(uid_t, struct passwd *, char *, size_t, struct passwd **))(dlsym(RTLD_NEXT, "getpwuid_r")))(uid, pwd, buf, buflen, result);
	if(retval != 0) {
		(*result)->pw_dir = getenv("HOME");
	}
	return retval;
}

