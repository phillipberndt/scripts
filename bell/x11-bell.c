#define XK_MISCELLANY
#define _BSD_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <X11/keysymdef.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/XKBlib.h>

int main(int argc, char *argv[]) {
	unsigned int auto_ctrls, auto_values;

	Display *display = XOpenDisplay(NULL);

	XkbSelectEvents(display, XkbUseCoreKbd, XkbBellNotifyMask, XkbBellNotifyMask);
	auto_ctrls = auto_values = XkbAudibleBellMask;
	XkbSetAutoResetControls(display, XkbAudibleBellMask, &auto_ctrls, &auto_values);
	XkbChangeEnabledControls(display, XkbUseCoreKbd, XkbAudibleBellMask, 0);

	daemon(0, 0);

	XEvent xev;
	while(True) {
		XNextEvent(display, &xev);

		if (((XkbEvent*) &xev)->any.xkb_type == XkbBellNotify) {
			system("bell");
		}
	}
}
