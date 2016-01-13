#!/usr/bin/env python
# encoding: utf-8
import check_integrity

for filename in check_integrity.list_files_with_enhanced_caps("/"):
    print filename
