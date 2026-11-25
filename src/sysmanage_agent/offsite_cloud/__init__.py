# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The off-site cloud copy of a storage host (server ROADMAP 27.3).

A storage host sends each of its ZFS datasets (the backup repositories, and
any other dataset the operator added) to an S3 bucket, normally in Glacier
Deep Archive: ``zfs send`` per dataset, a full and then incrementals, each
stream cut into parts, every part encrypted with AES-256 under a key only the
operator holds (``crypto``), and uploaded straight from this host to the
bucket (``s3``) -- no backup data passes through the SysManage server.  A
manifest per stream goes to S3 Standard, so a restore can be planned without
thawing anything.

The way back (thaw, download, decrypt, ``zfs receive``) is Community: it
works with no license and after a lapse.
"""
