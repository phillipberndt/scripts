/*
 * A very simple X11 lock
 *
 * Note: Google for 'AllowDeactivateGrabs' and/or 'AllowClosedownGrabs' for
 * potential security flaws! AFAIK, newer X-servers should not be affected.
 *
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * Note further: This is quite experimental. I am not experienced in Xlib
 * programming. If you need security, better use something like alock / xlock.
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * Compile with
 *  cc lock.c -lX11 -lpam -lXext
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#define XK_MISCELLANY
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <X11/keysymdef.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/dpms.h>
#include <security/pam_appl.h>
#include <pwd.h>

char passwordBuffer[255];

static unsigned long colors[] = {
	16711680ul, 16722432ul, 16733184ul, 16744192ul, 16755200ul, 16765952ul, 16776960ul, 13958912ul, 11206400ul, 8388352ul, 5570304ul, 2817792ul, 65280ul, 65322ul, 65365ul, 65407ul, 65449ul, 65492ul, 65535ul,
	54527ul, 43519ul, 32767ul, 21759ul, 11007ul, 255ul, 2752767ul, 5505279ul, 8323327ul, 11141375ul, 13893887ul, 16711935ul, 16711892ul, 16711850ul, 16711807ul, 16711765ul, 16711722ul,
};

int pam_nocomm(int __attribute__((unused)) n, const struct pam_message __attribute__((unused)) **query, struct pam_response **resp, void __attribute__((unused)) *data) {
	// PAM responder (responds with the password the user entered)
	*resp = (struct pam_response *)malloc(sizeof(struct pam_response));
	(*resp)->resp_retcode = 0;
	(*resp)->resp = malloc(255);
	strcpy((*resp)->resp, passwordBuffer);
	return PAM_SUCCESS;
}

int main(int argc, char *argv[]) {
	// Minimal options
	char fullscreen = 1;
	if(argc != 1) {
		if(strcmp(argv[1], "-h") == 0) {
			printf("lock. Use -n to not go to leave the desktop visible\n");
			return 0;
		}
		if(strcmp(argv[1], "-n") == 0) {
			fullscreen = 0;
		}
	}

	// Open Display
	Display *display = XOpenDisplay(NULL);
	XSetCloseDownMode(display, DestroyAll);

	// Initialize PAM
	pam_handle_t *pamh;
	struct pam_conv conv;
	conv.conv = pam_nocomm;
	if(pam_start("xscreensaver", (getpwuid(getuid()))->pw_name, &conv, &pamh) != PAM_SUCCESS) {
		exit(1);
	}

	// Create and map window
	XSetWindowAttributes at;
	at.override_redirect = 1;
	at.event_mask = KeyPressMask;

	Window w = XCreateWindow(display, DefaultRootWindow(display), 0, 0, 100, 100, 1, CopyFromParent, CopyFromParent, CopyFromParent, CWOverrideRedirect | CWEventMask, &at);

	XWindowAttributes xwa;
	XGetWindowAttributes(display, DefaultRootWindow(display), &xwa);
	if(fullscreen == 1) {
		XMoveResizeWindow(display, w, 0, 0, xwa.width, xwa.height);
	}
	else {
		XMoveResizeWindow(display, w, 0, 0, 1, 1);
	}

	XMapWindow(display, w);
	XRaiseWindow(display, w);
	XSync(display, False);

	// Wait for the WM to settle..
	sleep(1);

	// Grab Pointer & Keyboard
	for(int tries=0; XGrabPointer(display, w, False, ButtonPressMask | ButtonReleaseMask | EnterWindowMask | LeaveWindowMask | PointerMotionMask, GrabModeAsync, GrabModeAsync, w, None, CurrentTime) != GrabSuccess; tries++) {
		if(tries > 3) {
			exit(1);
		}
		sleep(1);
	}
	for(int tries=0; XGrabKeyboard(display, w, False, GrabModeAsync, GrabModeAsync, CurrentTime) != GrabSuccess; tries++) {
		if(tries > 3) {
			exit(1);
		}
		sleep(1);
	}

	XSetWindowBackground(display, w, 0);
	XClearWindow(display, w);
	XSync(display, False);

	XGCValues values;
	GC gc = XCreateGC(display, w, 0, &values);
	XSetForeground(display, gc, WhitePixel(display, 0));
	XSetBackground(display, gc, WhitePixel(display, 0));
	XSetFillStyle(display, gc, FillSolid);

	// Disable screen
	if(fullscreen == 1) {
		DPMSForceLevel(display, DPMSModeOff);
	}

	// Read password from keyboard events,
	// verify, loop where required
	XEvent xev;
	char inputBuffer[4];
	int passwordBufferLength = 0;
	while(True) {
		// Read password
		passwordBufferLength = 0;
		while(True) {
			int changed = 0;
			XNextEvent(display, &xev);

			if(xev.type != 2 /* KeyPress */) {
				continue;
			}

			KeySym keysym = XLookupKeysym((XKeyEvent *)&xev, 0);
			if(keysym == XK_BackSpace) {
				if(passwordBufferLength > 0) {
					passwordBufferLength--;
					changed = 1;
				}
			}
			else if(keysym == XK_Return) {
				break;
			}
			else if(XLookupString((XKeyEvent *)&xev, inputBuffer, 4, NULL, NULL) == 1) {
				int len = strlen(inputBuffer);

				if(passwordBufferLength + len < (int)sizeof(passwordBuffer)) {
					memcpy(passwordBuffer + passwordBufferLength, inputBuffer, len);
					passwordBufferLength += len;
					changed = 1;
				}
			}

			if(changed) {
				// Draw current square
				int i = passwordBufferLength - 1;
				if(i >= 0) {
					XSetForeground(display, gc, colors[(7 * i) % (sizeof(colors) / sizeof(colors[0]))]);
					XFillRectangle(display, w, gc, 20 + i * 40, 20, 20, 20);
					XFillRectangle(display, w, gc, xwa.width - 20 - i * 40, xwa.height - 40, 20, 20);

					XSetForeground(display, gc, WhitePixel(display, 0));
					XDrawRectangle(display, w, gc, 20 + i * 40, 20, 20, 20);
					XDrawRectangle(display, w, gc, xwa.width - 20 - i * 40, xwa.height - 40, 20, 20);
				}

				// Black out next square (to handle backspace)
				i++;
				XSetForeground(display, gc, BlackPixel(display, 0));
				XFillRectangle(display, w, gc, 20 + i * 40 - 1, 19, 22, 22);
				XFillRectangle(display, w, gc, xwa.width - 20 - i * 40 - 1, xwa.height - 40 - 1, 22, 22);
			}
		}
		passwordBuffer[passwordBufferLength] = 0;
		XClearWindow(display, w);
		XSync(display, False);

		// Verify password
		pam_set_item(pamh, PAM_AUTHTOK, passwordBuffer);
		if(pam_authenticate(pamh, PAM_SILENT) == PAM_SUCCESS) {
			break;
		}
	}

	// Clean up
	pam_end(pamh, 0);
	XUnmapWindow(display, w);
	XUngrabServer(display);
	XFlush(display);
	return 0;
}
