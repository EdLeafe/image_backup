#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pyrax

ctx = pyrax.create_context(env="rax")
ctx.keyring_auth()
comp = ctx.get_client("compute", "DFW")
print "COMP", comp.list()
