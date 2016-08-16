#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import datetime
import json
import logging
import logging.handlers
import os
import sys

from novaclient.exceptions import NotFound
import pyrax
import pyrax.exceptions as exc
pyrax.set_setting("identity_type", "rackspace")


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler()
formatter = logging.Formatter("RackspaceImageScheduler: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
handler = logging.FileHandler("/home/ed/projects/image_backup/logs/image_backup.log")
formatter = logging.Formatter("%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


# If running under cron, 'INTERACTIVE' will be False
INTERACTIVE = os.isatty(sys.stdin.fileno())


def logit(msg):
    if INTERACTIVE:
        print msg
    logger.info(msg)


# Local file for storing configuration settings.
CONFIG_FILE = os.path.expanduser("~/.image_backup.cfg")


class SettingsHolder(object):
    username = None
    api_key = None
    instance_ids = None
    backup_count = None

    def __init__(self, args):
        try:
            with file(CONFIG_FILE, "rb") as cfile:
                dct = json.load(cfile)
        except (IOError, ValueError) as e:
            logit("Could not read config file: %s" % e)
            dct = {}
        self.from_dict(dct)
        # Override with any non-None args
        for arg in ("username", "api_key", "server_id", "backup_count"):
            val = getattr(args, arg)
            if val is not None:
                if arg == "server_id":
                    # Naming difference
                    self.instance_ids = val
                else:
                    setattr(self, arg, val)

    def save(self):
        dct = self.to_dict()
        with file(CONFIG_FILE, "w") as cfile:
            json.dump(dct, cfile)

    def from_dict(self, dct):
        for att in dct:
            setattr(self, att, dct[att])

    def to_dict(self):
        atts = [att for att in self.__dict__ if not att.startswith("_")]
        ret = {}
        for att in atts:
            val = getattr(self, att)
            if val is not None:
                ret[att] = val
        return ret

    def get_missing(self):
        missing = []
        if not self.username:
            missing.append("username")
        if not self.api_key:
            missing.append("api_key")
        if not self.instance_ids:
            missing.append("instance_ids")
        if not self.backup_count:
            missing.append("backup_count")
        return ", ".join(missing)


def main(username=None, api_key=None, server_ids=None, backup_count=None):
    parser = argparse.ArgumentParser(description="Run regularly scheduled images of a cloud server.")
    parser.add_argument("--username", "-u",  help="The account's username")
    parser.add_argument("--api-key", "-k",  help="The account's API key")
    parser.add_argument("--server-id", "-s", action="append", help="The ID of the server to back up. "
            "You may specify this parameter multiple times to back up multiple servers.")
    parser.add_argument("--backup-count", "-b", type=int, help="Number of backups to retain per server. "
            "After this limit is reached, the oldest backups will be deleted.")
    parser.add_argument("--persist", "-p", action="store_true", help="Store the values specified as "
            "parameters in this call to be used as the default in future runs.")
    args = parser.parse_args()

    settings = SettingsHolder(args)
    # If passed directly to this method, use those values.
    if username:
        settings.username = username
    if api_key:
        settings.api_key = api_key
    if server_ids:
        settings.instance_ids = server_ids
    if backup_count:
        settings.backup_count = backup_count

    if isinstance(settings.instance_ids, basestring):
        settings.instance_ids = json.loads(settings.instance_ids)
    if args.persist:
        settings.save()

    if INTERACTIVE:
        if not settings.username:
            settings.username = raw_input("Please enter the account username: ")
            if not settings.username:
                logit("Cannot continue without account username.")
                sys.exit()
        if not settings.api_key:
            settings.api_key = raw_input("Please enter the account API key: ")
            if not settings.api_key:
                logit("Cannot continue without account API key.")
                sys.exit()

        if not settings.instance_ids:
            print " ".join(["Please enter the ID of the server(s) to backup.",
                    "You may enter more than one ID, separated by spaces."])
            input_ids = raw_input()
            if not input_ids:
                logit("Cannot continue without ID of instance.")
                sys.exit()
            # Strip commas, in case they added them to the input
            input_ids = input_ids.replace(",", "")
            settings.instance_ids = [iid.strip() for iid in instance_ids.split(" ")]

        if not settings.backup_count:
            settings.backup_count = raw_input("How many backup images should be retained? ")
            if not settings.backup_count:
                logit("Cannot continue without backup count.")
                sys.exit()
        settings.backup_count = int(settings.backup_count)
    else:
        # All values must be defined to continue
        missing = settings.get_missing()
        if missing:
            logit("Could not continue; the following values are missing: %s" % missing)
            sys.exit()

    ctxt = pyrax.create_context()
    try:
        ctxt.authenticate(settings.username, settings.api_key)
    except exc.AuthenticationFailed:
        logit("Unable to authenticate.")
        sys.exit()
    # Turn off debug output
    pyrax.set_http_debug(False)

    #TODO: add support for other regions
    cs_dfw = ctxt.get_client("compute", "DFW")
    cs_ord = ctxt.get_client("compute", "ORD")
    regions = (cs_dfw, cs_ord)
    now = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    for instance_id in settings.instance_ids:
        instance = None
        last_region = None
        for region in regions:
            try:
                instance = region.servers.get(instance_id)
                logit("Found instance '%s' in region '%s'" % (instance.name, region.client.region_name))
                break
            except exc.ServerNotFound:
                continue

        if not instance:
            # Instance not found
            continue
        image_name = "%s-%s" % (instance.name, now)

        if region != last_region:
            images = region.list_snapshots()
            last_region = region
        backups = [image for image in images
                if image.name.startswith(instance.name)]
        # Sorting by name will result in the oldest first.
        backups.sort(lambda x,y: cmp(x.name, y.name))

        to_delete = []
        # Don't delete just yet; the image creation step below
        # could fail.
        while len(backups) >= settings.backup_count:
            to_delete.append(backups.pop(0))

        try:
            instance.create_image(image_name)
            logit("Successfully created backup image: %s" % image_name)
        except exc.ServerClientException as e:
            logit("Unable to create image: %s" % e)
            continue

        for old_image in to_delete:
            try:
                old_image.delete()
                logit("Deleted old image: %s" % old_image.name)
            except NotFound:
                logit("Could not delete old image: %s" % old_image.name)


if __name__ == "__main__":
    if not INTERACTIVE:
        logit("Called from cron.")
    try:
        main()
        logit("Done.")
    except Exception as e:
        logit("Exception: %s" % e)
