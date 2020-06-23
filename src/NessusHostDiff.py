import os
import sqlite3
import argparse
from datetime import datetime
import mysql.connector as mysql
import sys

SQLITE3_DB = "/tmp/nessus_import.db"


class NessusHostDiff:
    def __init__(self, report_folder_names, report_scanids, network):
        self.use_mysql = os.getenv("USE_MYSQL", False)
        self.mysql_config = {
            "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
            "user": os.getenv("MYSQL_USER", "root"),
            "passwd": os.getenv("MYSQL_PASSWD", "synd1337"),
            "port": os.getenv("MYSQL_PORT", "3305"),
            "database": os.getenv("MYSQL_DATABASE", "nessus_scans"),
        }
        self.report_folder_names = report_folder_names.split(",")
        self.report_scanids = report_scanids.split(",")
        self.network = network

    def create_import_table(self):
        if self.use_mysql:
            db = mysql.connect(**self.mysql_config)
            cur = db.cursor()
        else:
            db = sqlite3.connect(SQLITE3_DB)
            cur = db.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS nessus_diff (
            diff varchar(255),
            host varchar(255),
            port varchar(255),
            protocol varchar(255),
            state varchar(255),
            folder_name varchar(255),
            scan_start timestamp,
            scan_end timestamp,
            scan_id varchar(255),
            scan_uuid varchar(255),
            scan_diff varchar(255),
            network varchar(255)
            )
            """
        )

    def check_scan_uuid_exists(self, scan_uuid):
        sql = f"select count(1) from nessus_diff where scan_uuid='{scan_uuid}'"
        if self.use_mysql:
            db = mysql.connect(**self.mysql_config)
            cur = db.cursor()
        else:
            db = sqlite3.connect(SQLITE3_DB)
            cur = db.cursor()
        try:
            cur.execute(sql)
            rv = cur.fetchall()
            return rv[0][0]
        except Exception as e:
            print(e)
            sys.exit(1)

    def get_scan_uuid_list(self):
        if self.use_mysql:
            db = mysql.connect(**self.mysql_config)
            cur = db.cursor()
        else:
            db = sqlite3.connect(SQLITE3_DB)
            cur = db.cursor()
        folders = ", ".join("'{}'".format(x) for x in self.report_folder_names)
        scanids = ", ".join("'{}'".format(x) for x in self.report_scanids)
        SQL = (
            f"select distinct scan_id, scan_uuid, scan_start, folder_name "
            f"from nessus_import where folder_name in ({folders}) "
            f"and scan_id in ({scanids}) "
            f"order by scan_start desc"
        )
        cur.execute(SQL)
        rv = cur.fetchall()
        return rv

    def parse_date(self, date):
        dt = datetime.timestamp(date)
        return dt

    def create_reports(self):
        if self.use_mysql:
            db = mysql.connect(**self.mysql_config)
            cur = db.cursor()
        else:
            db = sqlite3.connect(SQLITE3_DB)
            cur = db.cursor()
        scans = self.get_scan_uuid_list()
        report_count = 0
        report_length = len(scans)
        while report_count < (report_length - 1):
            if not self.check_scan_uuid_exists(scans[report_count][1]):
                if self.use_mysql:
                    NEW_SQL = (
                        f"insert into nessus_diff select *, '{self.network}' as network from "
                        f"(select distinct concat(host,'_', port) as diff, host, port, protocol, 'NEW' as state, "
                        f"folder_name, scan_start, scan_end, scan_id, scan_uuid, "
                        f"'{scans[report_count][1]}_{scans[report_count+1][1]}' as scan_diff from nessus_import "
                        f"where scan_uuid='{scans[report_count][1]}' and plugin_id='11219') d "
                        f"where d.diff not in "
                        f"(select distinct concat(host,'_', port) as diff from  nessus_import "
                        f"where scan_uuid='{scans[report_count+1][1]}' and plugin_id='11219')"
                    )
                    LOST_SQL = (
                        f"insert into nessus_diff select *, '{self.network}' as network from  "
                        f"(select distinct concat(host,'_', port) as diff, host, port, protocol, 'LOST' as state, "
                        f"'{scans[report_count][3]}' as folder_name, "
                        f"'{scans[report_count][2]}' as scan_start, scan_end, scan_id, '"
                        f"{scans[report_count][1]}' as scan_uuid, "
                        f"'{scans[report_count][1]}_{scans[report_count + 1][1]}' as scan_diff from nessus_import "
                        f"where scan_uuid='{scans[report_count + 1][1]}' and plugin_id='11219') d "
                        f"where d.diff not in "
                        f"(select distinct concat(host,'_', port) as diff from  nessus_import "
                        f"where scan_uuid='{scans[report_count][1]}' and plugin_id='11219')"
                    )
                else:
                    NEW_SQL = (
                        f"insert into nessus_diff select *, '{self.network}' as network from "
                        f"(select distinct host || '_' || port as diff, host, port, protocol, 'NEW' as state, "
                        f"folder_name, scan_start, scan_end, scan_id, scan_uuid, "
                        f"'{scans[report_count][1]}_{scans[report_count + 1][1]}' as scan_diff from nessus_import "
                        f"where scan_uuid='{scans[report_count][1]}' and plugin_id='11219') d "
                        f"where d.diff not in "
                        f"(select distinct host || '_' || port as diff from  nessus_import "
                        f"where scan_uuid='{scans[report_count + 1][1]}' and plugin_id='11219')"
                    )
                    LOST_SQL = (
                        f"insert into nessus_diff select *, '{self.network}' as network from  "
                        f"(select distinct host || '_' || port as diff, host, port, protocol, 'LOST' as state, "
                        f"'{scans[report_count][3]}' as folder_name, "
                        f"'{scans[report_count][2]}' as scan_start, scan_end, scan_id, '"
                        f"{scans[report_count][1]}' as scan_uuid, "
                        f"'{scans[report_count][1]}_{scans[report_count + 1][1]}' as scan_diff from nessus_import "
                        f"where scan_uuid='{scans[report_count + 1][1]}' and plugin_id='11219') d "
                        f"where d.diff not in "
                        f"(select distinct host || '_' || port as diff from  nessus_import "
                        f"where scan_uuid='{scans[report_count][1]}' and plugin_id='11219')"
                    )
                # import pdb; pdb.set_trace()
                cur.execute(NEW_SQL)
                cur.execute(LOST_SQL)
                db.commit()
            else:
                print("Print scan_uuid already processed {}".format(scans[report_count][1]))
            report_count += 1


def setup_parser(parser):
    """
    Generate Host diff Nessus scans
    """
    parser.add_argument("folder_names", help="List of folder name i.e. Internal")
    parser.add_argument("scan_ids", help="list of scanids i.e. 10,20,30")
    parser.add_argument("network", help="network name tag for the diff")
    parser.set_defaults(func=main)
    return parser


def main(args):
    report = NessusHostDiff(args.folder_names, args.scan_ids, args.network)
    report.create_import_table()
    report.create_reports()


if __name__ == "__main__":
    parser = setup_parser(argparse.ArgumentParser())
    args = parser.parse_args()
    args.func(args)
