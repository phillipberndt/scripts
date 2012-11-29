#!/usr/bin/env python
# vim:fileencoding=utf-8
import os
import xml.dom.minidom
import urllib

weather = xml.dom.minidom.parseString(urllib.urlopen("http://weather.yahooapis.com/forecastrss?w=638242&u=c").read())
cond = weather.documentElement.getElementsByTagName("yweather:condition")[0]

text = cond.getAttribute("text")
code = cond.getAttribute("code")
temp = cond.getAttribute("temp")

codeToKey = {
	0:	"w",
	1:	"v",
	2:	"v",
	3:	"i",
	4:	"f",
	5:	"k",
	6:	"h",
	7:	"k",
	8:	"j",
	9:	"g",
	10:	"h",
	11:	"h",
	12:	"h",
	13:	"k",
	14:	"k",
	15:	"k",
	16:	"k",
	17:	"h",
	18:	"h",
	19:	"e",
	20:	"e",
	21:	"d",
	22:	"d",
	23:	"d",
	24:	"b",
	25:	"j",
	26:	"c",
	27:	"o",
	28:	"c",
	29:	"m",
	30:	"b",
	31:	"K",
	32:	"a",
	33:	"K",
	34:	"b",
	35:	"h",
	36:	"a",
	37:	"f",
	38:	"f",
	39:	"f",
	40:	"f",
	41:	"k",
	42:	"k",
	43:	"k",
	44:	"b",
	45:	"k",
	46:	"k",
	47:	"f",
	3200:	"?",
}

textout = temp + " C (" + text + ", " + code + ")"

if int(code) in codeToKey:
	codeout = codeToKey[int(code)]
else:
	coutout = "?"

print "${voffset -25}${font weather:size=100}${color black}" + codeout + "${font}${voffset -45}  " + textout
