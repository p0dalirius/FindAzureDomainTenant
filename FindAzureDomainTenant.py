#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : FindAzureDomainTenant.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Apr 2023

import argparse
import datetime
import json
import os
import traceback
import requests
import sqlite3
import sys
import threading
import time
import xlsxwriter
from concurrent.futures import ThreadPoolExecutor


VERSION = "1.1"


def export_xlsx(data, path_to_file):
    print("[>] Writing '%s' ... " % path_to_file, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(path_to_file)
    filename = os.path.basename(path_to_file)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename

    workbook = xlsxwriter.Workbook(path_to_file)
    worksheet = workbook.add_worksheet()

    header_format = workbook.add_format({'bold': 1})
    header_fields = ["Tenant ID", "Domain", "Region"]
    for k in range(len(header_fields)):
        worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
    worksheet.set_row(0, 20, header_format)
    worksheet.write_row(0, 0, header_fields)

    row_id = 1
    for tenant_id in data.keys():
        for domain in data[tenant_id]:
            worksheet.write_row(row_id, 0, [
                tenant_id,
                domain["domain"],
                domain["tenant_region_scope"]
            ])
            row_id += 1
    worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
    workbook.close()
    print("done.")


def export_json(data, path_to_file):
    print("[>] Writing '%s' ... " % path_to_file, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(path_to_file)
    filename = os.path.basename(path_to_file)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename
    f = open(path_to_file, 'w')
    f.write(json.dumps(data, indent=4))
    f.close()
    print("done.")


def export_sqlite(data, path_to_file):
    print("[>] Writing '%s' ... " % path_to_file, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(path_to_file)
    filename = os.path.basename(path_to_file)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename

    conn = sqlite3.connect(path_to_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS results(tenant_id VARCHAR(255), domain VARCHAR(255), region VARCHAR(255));")
    for tenant_id in data.keys():
        for domain in data[tenant_id]:
            cursor.execute("INSERT INTO results VALUES (?, ?, ?)", (
                    tenant_id,
                    domain["domain"],
                    domain["tenant_region_scope"]
                )
            )
    conn.commit()
    conn.close()
    print("done.")


def monitor_thread(options, monitor_data, only_check_finished=False):
    time.sleep(1)
    last_check, monitoring = 0, True
    while monitoring:
        new_check = monitor_data["actions_performed"]
        rate = (new_check - last_check)
        monitor_data["lock"].acquire()
        if monitor_data["total"] == 0:
            print("\r[%s] Status (%d/%d) %5.2f %% | Rate %d tests/s        " % (
                    datetime.datetime.now().strftime("%Y/%m/%d %Hh%Mm%Ss"),
                    new_check, monitor_data["total"], 0,
                    rate
                ),
                end=""
            )
        else:
            print("\r[%s] Status (%d/%d) %5.2f %% | Rate %d tests/s        " % (
                    datetime.datetime.now().strftime("%Y/%m/%d %Hh%Mm%Ss"),
                    new_check, monitor_data["total"], (new_check / monitor_data["total"]) * 100,
                    rate
                ),
                end=""
            )
        last_check = new_check
        monitor_data["lock"].release()
        time.sleep(1)
        if only_check_finished:
            if monitor_data["finished"]:
                monitoring = False
        else:
            if rate == 0 and monitor_data["actions_performed"] == monitor_data["total"] or monitor_data["finished"]:
                monitoring = False
    print()


def check_if_tenant_exists(domain, options, request_proxies, monitor_data):
    try:
        r = requests.get(
            f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration",
            timeout=options.request_timeout,
            proxies=request_proxies
        )
        data = r.json()
        if "error" in data.keys():
            if data["error"] == "invalid_tenant":
                # https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes#aadsts-error-codes
                err_code = data["error_description"].split(':')[0].strip()
            if options.debug and False:
                print("[!] %s => %s" % (domain, data["error"]))
        elif "token_endpoint" in data.keys():
            tenant_id = data["token_endpoint"].split("/")[3]
            if tenant_id not in monitor_data["tenants"].keys():
                monitor_data["tenants"][tenant_id] = []
            monitor_data["tenants"][tenant_id].append({
                "id": tenant_id,
                "domain": domain,
                "tenant_region_scope": data["tenant_region_scope"],
                "data": data
            })
            if options.no_colors:
                print("\r[+] tenant-id:%s domain:%s region:%s" % (tenant_id, domain, data["tenant_region_scope"]))
            else:
                print("\r[+] tenant-id:\x1b[1;92m%s\x1b[0m domain:\x1b[1;96m%s\x1b[0m region:\x1b[1;95m%s\x1b[0m" % (tenant_id, domain, data["tenant_region_scope"]))

    except Exception as e:
        traceback.print_exc()

    monitor_data["actions_performed"] += 1

    return None


def parseArgs():
    print("FindAzureDomainTenant.py v%s - by @podalirius_\n" % VERSION)

    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    parser.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")
    parser.add_argument("-T", "--threads", default=8, type=int, help="Number of threads (default: 8)")
    parser.add_argument("--no-colors", default=False, action="store_true", help="Disable colored output. (default: False)")

    group_configuration = parser.add_argument_group("Advanced configuration")
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, type=str, help="Proxy IP.")
    group_configuration.add_argument("-PP", "--proxy-port", default=None, type=int, help="Proxy port.")
    group_configuration.add_argument("-rt", "--request-timeout", default=5, type=int, help="Set the timeout of HTTP requests.")

    group_export = parser.add_argument_group("Export results")
    group_export.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    group_export.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    group_export.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    group_targets_source = parser.add_argument_group("Tenants")
    group_targets_source.add_argument("-tf", "--tenants-file", default=None, type=str, help="Path to file containing a line by line list of tenants names.")
    group_targets_source.add_argument("-tt", "--tenant", default=[], type=str, action='append', help="Tenant name.")
    group_targets_source.add_argument("--stdin", default=False, action="store_true", help="Read targets from stdin. (default: False)")

    options = parser.parse_args()

    if (options.tenants_file is None) and (options.stdin == False) and (len(options.tenant) == 0):
        parser.print_help()
        print("\n[!] No tenants specified.")
        sys.exit(0)

    return options


if __name__ == '__main__':
    options = parseArgs()

    request_proxies = {}
    if options.proxy_ip is not None and options.proxy_port is not None:
        request_proxies = {
            "http": "http://%s:%d/" % (options.proxy_ip, options.proxy_port),
            "https": "https://%s:%d/" % (options.proxy_ip, options.proxy_port)
        }

    tenants = []

    # Loading targets line by line from a tenants file
    if options.tenants_file is not None:
        if os.path.exists(options.tenants_file):
            if options.debug:
                print("[debug] Loading tenants line by line from targets file '%s'" % options.tenants_file)
            f = open(options.tenants_file, "r")
            for line in f.readlines():
                tenants.append(line.strip())
            f.close()
        else:
            print("[!] Could not open tenants file '%s'" % options.tenants_file)

    # Loading targets from a single --tenant option
    if len(options.tenant) != 0:
        if options.debug:
            print("[debug] Loading tenants from --target options")
        for tenant in options.tenant:
            tenants.append(tenant)

    if len(tenants) != 0:
        print("[>] Checking %d tenants if they exists" % len(tenants))
        monitor_data = {"actions_performed": 0, "total": len(tenants), "tenants": {}, "lock": threading.Lock(), "finished": False}
        with ThreadPoolExecutor(max_workers=min(options.threads, (len(tenants)+1))) as tp:
            tp.submit(monitor_thread, options, monitor_data, False)
            for tenant in tenants:
                tp.submit(check_if_tenant_exists, tenant, options, request_proxies, monitor_data)

        if options.export_xlsx is not None:
            export_xlsx(monitor_data["tenants"], options.export_xlsx)

        if options.export_json is not None:
            export_json(monitor_data["tenants"], options.export_json)

        if options.export_sqlite is not None:
            export_sqlite(monitor_data["tenants"], options.export_sqlite)

        print("[>] All done!")

    elif options.stdin:
        print("[>] Checking tenants from stdin if they exists")
        monitor_data = {"actions_performed": 0, "total": 0, "tenants": {}, "lock": threading.Lock(), "finished": False}
        with ThreadPoolExecutor(max_workers=options.threads) as tp:
            tp.submit(monitor_thread, options, monitor_data, True)
            try:
                while True:
                    tenant = input()
                    monitor_data["total"] += 1
                    tp.submit(check_if_tenant_exists, tenant, options, request_proxies, monitor_data)
            except EOFError as e:
                pass

        if options.export_xlsx is not None:
            export_xlsx(monitor_data["tenants"], options.export_xlsx)

        if options.export_json is not None:
            export_json(monitor_data["tenants"], options.export_json)

        if options.export_sqlite is not None:
            export_sqlite(monitor_data["tenants"], options.export_sqlite)

        print("[>] All done (%d tenants checked)!" % (monitor_data["actions_performed"]))

    else:
        print("[!] No tenants to find.")

