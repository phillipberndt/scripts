#!/usr/bin/env python
# encoding: utf-8
#
# Tiny redshift alternative.
#
# Can only set all outputs to one temperature in one shot, and then exit. No
# fancy transitions, auto geolocation, etc. Works with X11 only.
#
import ctypes
import itertools
import re
import subprocess
import sys

BLACK_BODY_COLORS = [
    # Taken from https://github.com/jonls/redshift/blob/master/README-colorramp
    # Starting from 1000 K, in 100 K steps
    0xff2e00, 0xff4100, 0xff4e00, 0xff5a00, 0xff6300, 0xff6b00, 0xff7300, 0xff7900, 0xff7f00, 0xff8400,
    0xff8a16, 0xff9023, 0xff952e, 0xff9a38, 0xff9f41, 0xffa449, 0xffa851, 0xffac58, 0xffb05f, 0xffb466,
    0xffb76d, 0xffba73, 0xffbe79, 0xffc17f, 0xffc485, 0xffc68b, 0xffc990, 0xffcc96, 0xffce9b, 0xffd0a0,
    0xffd3a5, 0xffd5aa, 0xffd7ae, 0xffd9b3, 0xffdbb7, 0xffddbb, 0xffdfc0, 0xffe1c4, 0xffe2c8, 0xffe4cb,
    0xffe6cf, 0xffe7d3, 0xffe9d6, 0xffebda, 0xffeddd, 0xffefe0, 0xfff1e3, 0xfff2e7, 0xfff4ea, 0xfff6ed,
    0xfff7f0, 0xfff9f3, 0xfffaf6, 0xfffcf9, 0xfffdfc, 0xffffff, 0xfcfdff, 0xf9fbff, 0xf7faff, 0xf4f8ff,
    0xf2f7ff, 0xf0f5ff, 0xeef4ff, 0xecf3ff, 0xeaf2ff, 0xe8f0ff, 0xe6efff, 0xe5eeff, 0xe3edff, 0xe1ecff,
    0xe0ebff, 0xdeeaff, 0xdde9ff, 0xdbe8ff, 0xdae7ff, 0xd9e6ff, 0xd7e6ff, 0xd6e5ff, 0xd5e4ff, 0xd4e3ff,
    0xd3e2ff, 0xd2e2ff, 0xd0e1ff, 0xcfe0ff, 0xcee0ff, 0xcddfff, 0xccdeff, 0xccdeff, 0xcbddff, 0xcaddff,
    0xc9dcff, 0xc8dbff, 0xc7dbff, 0xc6daff, 0xc6daff, 0xc5d9ff, 0xc4d9ff, 0xc4d8ff, 0xc3d8ff, 0xc2d8ff,
    0xc1d7ff, 0xc1d7ff, 0xc0d6ff, 0xc0d6ff, 0xbfd5ff, 0xbed5ff, 0xbed5ff, 0xbdd4ff, 0xbdd4ff, 0xbcd3ff,
    0xbcd3ff, 0xbbd3ff, 0xbbd2ff, 0xbad2ff, 0xbad2ff, 0xb9d1ff, 0xb9d1ff, 0xb8d1ff, 0xb8d0ff, 0xb7d0ff,
    0xb7d0ff, 0xb6d0ff, 0xb6cfff, 0xb6cfff, 0xb5cfff, 0xb5ceff, 0xb4ceff, 0xb4ceff, 0xb4ceff, 0xb3cdff,
    0xb3cdff, 0xb3cdff, 0xb2cdff, 0xb2ccff, 0xb2ccff, 0xb1ccff, 0xb1ccff, 0xb1ccff, 0xb0cbff, 0xb0cbff,
    0xb0cbff, 0xafcbff, 0xafcaff, 0xafcaff, 0xafcaff, 0xaecaff, 0xaecaff, 0xaecaff, 0xaec9ff, 0xadc9ff,
    0xadc9ff, 0xadc9ff, 0xacc9ff, 0xacc8ff, 0xacc8ff, 0xacc8ff, 0xacc8ff, 0xabc8ff, 0xabc8ff, 0xabc7ff,
    0xabc7ff, 0xaac7ff, 0xaac7ff, 0xaac7ff, 0xaac7ff, 0xaac7ff, 0xa9c6ff, 0xa9c6ff, 0xa9c6ff, 0xa9c6ff,
    0xa9c6ff, 0xa8c6ff, 0xa8c6ff, 0xa8c6ff, 0xa8c5ff, 0xa8c5ff, 0xa7c5ff, 0xa7c5ff, 0xa7c5ff, 0xa7c5ff,
    0xa7c5ff, 0xa7c5ff, 0xa6c4ff, 0xa6c4ff, 0xa6c4ff, 0xa6c4ff, 0xa6c4ff, 0xa6c4ff, 0xa6c4ff, 0xa5c4ff,
    0xa5c4ff, 0xa5c3ff, 0xa5c3ff, 0xa5c3ff, 0xa5c3ff, 0xa5c3ff, 0xa4c3ff, 0xa4c3ff, 0xa4c3ff, 0xa4c3ff,
    0xa4c3ff, 0xa4c2ff, 0xa4c2ff, 0xa3c2ff, 0xa3c2ff, 0xa3c2ff, 0xa3c2ff, 0xa3c2ff, 0xa3c2ff, 0xa3c2ff,
    0xa3c2ff, 0xa2c2ff, 0xa2c2ff, 0xa2c1ff, 0xa2c1ff, 0xa2c1ff, 0xa2c1ff, 0xa2c1ff, 0xa2c1ff, 0xa2c1ff,
    0xa1c1ff, 0xa1c1ff, 0xa1c1ff, 0xa1c1ff, 0xa1c1ff, 0xa1c1ff, 0xa1c0ff, 0xa1c0ff, 0xa1c0ff, 0xa1c0ff,
    0xa0c0ff, 0xa0c0ff, 0xa0c0ff, 0xa0c0ff, 0xa0c0ff, 0xa0c0ff, 0xa0c0ff, 0xa0c0ff, 0xa0c0ff, 0xa0c0ff,
    0xa0c0ff, 0x9fbfff,
]

DEFAULT_TEMPERATURE = 6500

libX11 = ctypes.CDLL("libX11.so")
libX11.XOpenDisplay.restype = ctypes.c_voidp

libXrandr = ctypes.CDLL("libXrandr.so")
class XRRScreenResources(ctypes.Structure):
    _fields_ = [("timestamp", ctypes.c_ulong),
                ("configTimestamp", ctypes.c_ulong),
                ("ncrtc", ctypes.c_int),
                ("crtcs", ctypes.POINTER(ctypes.c_long)),
                ("noutput", ctypes.c_int),
                ("outputs", ctypes.POINTER(ctypes.c_long)),
                ("nmode", ctypes.c_int),
                ("modes", ctypes.POINTER(ctypes.c_long))]
libXrandr.XRRGetScreenResources.restype = ctypes.POINTER(XRRScreenResources)

class XRRCrtcGamma(ctypes.Structure):
    _fields_ = [("size", ctypes.c_int),
                ("red", ctypes.POINTER(ctypes.c_ushort)),
                ("green", ctypes.POINTER(ctypes.c_ushort)),
                ("blue", ctypes.POINTER(ctypes.c_ushort))]
libXrandr.XRRAllocGamma.restype = ctypes.POINTER(XRRCrtcGamma)

def rgb_for_blackbody(temperature):
    "Return a RGB tuple for the color of a blackbody at a given temperature"
    hex2rgb = lambda x: ((x & 0xff0000) >> 16, (x & 0xff00) >> 8, x & 0xff)

    interpolate_lower_index = int((temperature - 1000) // 100)
    assert 0 < interpolate_lower_index + 1 < len(BLACK_BODY_COLORS)
    y1 = hex2rgb(BLACK_BODY_COLORS[interpolate_lower_index])
    y2 = hex2rgb(BLACK_BODY_COLORS[interpolate_lower_index + 1])

    return tuple((yv1 + (yv2 - yv1) / 100. *
                  (temperature - 1000 - interpolate_lower_index * 100)) / 255.
                 for yv1, yv2 in zip(y1, y2))

def colorramp(size, whitepoint, brightness=1., gamma=(1.,1.,1.)):
    "Return a colorramp of the given size and whitepoint values"
    ramps = [ [], [], [] ]
    for i in range(size):
        value = i * 1. / size
        for color in range(3):
            ramps[color].append((value * whitepoint[color] * brightness) ** gamma[color])
    return ramps

def set_whitepoint(whitepoint, brightness, gamma):
    """Set a given whitepoint on all CRTCs using RandR

        We need to use the library for this, because xrandr does not support
        custom color ramps, only gamma corrections that are power functions of
        an index. See
        http://cgit.freedesktop.org/xorg/app/xrandr/tree/xrandr.c#n1104 for
        what xrandr does with the setting: We want to set the ramps to
          map[i] = pow(i/n * brightness * whitepoint, 1/gamma), but xrandr sets them to
          map[i] = pow(i/n, gamma) * brightness,
        i.e. we cannot use Xrandr to actually set them
    """
    display = libX11.XOpenDisplay("")
    root_window = libX11.XDefaultRootWindow(display)
    screen_resources = libXrandr.XRRGetScreenResources(display, root_window)

    for i in range(screen_resources.contents.ncrtc):
        xid = screen_resources.contents.crtcs[i]
        ramp_size = libXrandr.XRRGetCrtcGammaSize(display, xid)
        crtc_gamma = libXrandr.XRRAllocGamma(ramp_size)
        ramp = colorramp(ramp_size, whitepoint, brightness, gamma)

        for j in range(ramp_size):
            crtc_gamma.contents.red[j]   = int(ramp[0][j] * 0xffff)
            crtc_gamma.contents.green[j] = int(ramp[1][j] * 0xffff)
            crtc_gamma.contents.blue[j]  = int(ramp[2][j] * 0xffff)

        libXrandr.XRRSetCrtcGamma(display, xid, crtc_gamma)

    libXrandr.XRRFreeScreenResources(screen_resources)
    libX11.XCloseDisplay(display)

if __name__ == '__main__':
    temperature = DEFAULT_TEMPERATURE
    try:
        temperature = float(sys.argv[1])
    except IndexError:
        pass
    except:
        print "Syntax: µredshift <color temperature> [brightness] [additional gamma correction]"
        print "%d K is used by default" % DEFAULT_TEMPERATURE
        sys.exit(1)
    brightness = 1. if len(sys.argv) < 3 else float(sys.argv[2])
    gamma = (1., 1., 1.) if len(sys.argv) < 4 else map(float, sys.argv[3].split(":"))
    set_whitepoint(rgb_for_blackbody(temperature), brightness, gamma)
