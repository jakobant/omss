import csv
import sys
import os
import sqlite3
import argparse
from datetime import datetime
import mysql.connector as mysql

SQLITE3_DB = "/tmp/nessus_import.db"
FILENNAME_FIELDS = 6

class NessusImport:
    '''
    Nessus Pro: Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,STIG Severity,CVSS v3.0 Base Score,CVSS Temporal Score,CVSS v3.0 Temporal Score,Risk Factor,BID,XREF,MSKB,Plugin Publication Date,Plugin Modification Date,Metasploit,Core Impact,CANVAS
    Nessus  Io: Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,Asset UUID,Vulnerability State,IP Address,FQDN,NetBios,OS,MAC Address,Plugin Family,CVSS Base Score,CVSS Temporal Score,CVSS Temporal Vector,CVSS Vector,CVSS3 Base Score,CVSS3 Temporal Score,CVSS3 Temporal Vector,CVSS3 Vector,System Type,Host Start,Host End
    Nessus  Sc:
    '''
    def __init__(self, nessus_type="Pro"):
        self.use_mysql = os.getenv("USE_MYSQL", False)
        self.mysql_config = {
            "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
            "user": os.getenv("MYSQL_USER", "root"),
            "passwd": os.getenv("MYSQL_PASSWD", "synd1337"),
            "port": os.getenv("MYSQL_PORT", "3305"),
            "database": os.getenv("MYSQL_DATABASE", "nessus_scans"),
        }
        self.nessus = nessus_type

    def create_import_table(self):
        if self.use_mysql:
            db = mysql.connect(**self.mysql_config)
            cur = db.cursor()
        else:
            cur = sqlite3.connect(SQLITE3_DB).cursor()
        if self.nessus == 'Pro':
            cur.execute(
            """
            CREATE TABLE IF NOT EXISTS nessus_import (
            folder_name varchar(255),
            scan_id varchar(255),
            scan_uuid varchar(255),
            scan_start timestamp,
            scan_end timestamp,
            file_name varchar(255),
            plugin_id int(20),
            cve varchar(255),
            cvss double NULL DEFAULT NULL,
            risk varchar(255),
            host varchar(255),
            protocol varchar(255),
            port varchar(255),
            name longtext,
            synopsis longtext,
            description longtext,
            solution longtext,
            see_also longtext,
            plugin_output longtext,
            stig_severity varchar(255),
            cvss_v3_0_base_score double,
            cvss_temporal_score double,
            cvss_v3_0_temporal_score double,
            risk_factor varchar(255),
            bid varchar(255),
            xref longtext,
            mskb varchar(255),
            plugin_publication_date timestamp default NULL,
            plugin_modification_date timestamp default NULL,
            metasploit varchar(255),
            core_impact varchar(255),
            canvas varchar(255) )
            """
            )
        else:
            #Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,Asset UUID,Vulnerability State,IP Address,FQDN, NetBios,OS,MAC Address,Plugin Family, CVSS Base Score,CVSS Temporal Score,CVSS Temporal Vector,CVSS Vector,CVSS3 Base Score,CVSS3 Temporal Score,CVSS3 Temporal Vector,CVSS3 Vector,System Type,Host Start,Host End
            cur.execute(
            """
            CREATE TABLE IF NOT EXISTS nessus_import (
            folder_name varchar(255),
            scan_id varchar(255),
            scan_uuid varchar(255),
            scan_start timestamp,
            scan_end timestamp,
            file_name varchar(255),
            plugin_id int(20),
            cve varchar(255),
            cvss double NULL DEFAULT NULL,
            risk varchar(255),
            host varchar(255),
            protocol varchar(255),
            port varchar(255),
            name longtext,
            synopsis longtext,
            description longtext,
            solution longtext,
            see_also longtext,
            plugin_output longtext,
            asset_uuid varchar(255),
            vulnerability_state varchar(255),
            ip_address varchar(255),
            fqdn varchar(255), 
            netbios varchar(255),
            os varchar(255),
            mac_address varchar(255),
            plugin_family varchar(255),
            cvss_base_score double,
            cvss_temporal_score double,
            cvss_temporal_vector double,
            cvss_vector double,
            cvss3_base_score double,
            cvss3_temporal_score double,
            cvss3_temporal_vector double,
            cvss3_vector double,
            system_type varchar(255),
            host_start timestamp default NULL,
            host_end timestamp default NULL )
            """
            )

    def clean_colnums(self, row):
        if self.nessus == 'Pro':
            # Double colnums: scan_id,
            for n in (2, 14, 15, 16, 17):
                if row[n] in (None, ""):
                    row[n] = 0.0
            for x in (10, 11, 12):
                row[x] = row[x].replace("\n", r"\n")
                row[x] = row[x].replace("\r", r"\r")
                row[x] = row[x].replace("%s", r".")
            for n in (21, 22):
                if row[n] in (None, ""):
                    row[n] = None
            return row
        else:
            # Double colnums: scan_id,
            for n in (2, 21, 22, 23, 24, 25, 26, 27, 28):
                if row[n] in (None, ""):
                    row[n] = 0.0
            for x in (10, 11, 12):
                row[x] = row[x].replace("\n", r"\n")
                row[x] = row[x].replace("\r", r"\r")
                row[x] = row[x].replace("%s", r".")
            for n in (30, 31):
                if row[n] in (None, ""):
                    row[n] = None
            return row

    def get_sql_insert(self, row):
        if self.use_mysql:
            return "INSERT INTO nessus_import VALUES(%s);" % ",".join(
                ("%s",) * (len(row) + FILENNAME_FIELDS)
            )
        else:
            return "INSERT INTO nessus_import VALUES(%s);" % ",".join(
                "?" * (len(row) + FILENNAME_FIELDS)
            )

    def check_scan_uuid_exists(self, scan_uuid):
        sql = f"select count(1) from nessus_import where scan_uuid='{scan_uuid}'"
        if self.use_mysql:
            db = mysql.connect(**self.mysql_config)
            cur = db.cursor()
        else:
            cur = sqlite3.connect(SQLITE3_DB).cursor()
        try:
            cur.execute(sql)
            rv = cur.fetchall()
            return rv[0][0]
        except Exception as e:
            print(e)
            sys.exit(1)



    def parse_filename(self, csv_file):
        """Populate tats from filename information"""
        basefile = os.path.basename(csv_file)
        data = basefile.split(("#"))
        if len(data) != FILENNAME_FIELDS:
            raise RuntimeError("Errors parsing filename fields")
        scan_start = data[3]
        scan_end = data[4]
        data[3] = datetime.fromtimestamp(int(scan_start))
        data[4] = datetime.fromtimestamp(int(scan_end))
        return data

    def csv_import(self, csv_file):
        if self.use_mysql:
            db = mysql.connect(**self.mysql_config)
            cur = db.cursor()
        else:
            db = sqlite3.connect(SQLITE3_DB)
            cur = db.cursor()
        filedata = self.parse_filename(csv_file)
        if self.check_scan_uuid_exists(filedata[2]):
            print("Already imported")
            return
        csv.register_dialect("comma", delimiter=",", doublequote=True)

        skip_header = True
        with open(csv_file) as f:
            reader = csv.reader(f, dialect="comma")
            for row in reader:
                # print(row)
                row = self.clean_colnums(row)
                stmt = self.get_sql_insert(row)
                data = filedata + row
                if not skip_header:
                    try:
                        cur.execute(stmt, data)
                    except Exception as e:
                        print(e)
                        sys.exit(1)
                skip_header = False
            db.commit()
        cur.close()


def setup_parser(parser):
    """
    Import nessus csv files to sql
    """
    parser.add_argument("scan_csv", help="External CSV scan results")
    parser.add_argument('--nessus_type', type=str, default="Pro", help='Nessus type: <Pro|Io|Sc')
    parser.set_defaults(func=main)
    return parser


def main(args):
    cvs_import = NessusImport(nessus_type=args.nessus_type)
    cvs_import.create_import_table()
    cvs_import.csv_import(args.scan_csv)


if __name__ == "__main__":
    parser = setup_parser(argparse.ArgumentParser())
    args = parser.parse_args()
    args.func(args)
