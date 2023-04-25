![](.github/banner.png)

<p align="center">
    A Python script to find tenant id and region from a list of domain names.
    <br>
    <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/FindAzureDomainTenant">
    <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
    <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
    <br>
</p>

## Features

 - [x] Find tenant id and region from a list of domain names.
 - [x] Export results in JSON with `--export-json <file.json>`.
 - [x] Export results in XLSX with `--export-xlsx <file.xlsx>`.
 - [x] Export results in SQLITE3  with `--export-sqlite <file.db>`.

## Usage

```
$ ./FindAzureDomainTenant.py -h
FindAzureDomainTenant.py v1.1 - by @podalirius_

usage: FindAzureDomainTenant.py [-h] [-v] [--debug] [-T THREADS] [--no-colors] [-PI PROXY_IP] [-PP PROXY_PORT] [-rt REQUEST_TIMEOUT] [--export-xlsx EXPORT_XLSX] [--export-json EXPORT_JSON] [--export-sqlite EXPORT_SQLITE]
                                [-tf TENANTS_FILE] [-tt TENANT] [--stdin]

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode. (default: False)
  --debug               Debug mode, for huge verbosity. (default: False)
  -T THREADS, --threads THREADS
                        Number of threads (default: 8)
  --no-colors           Disable colored output. (default: False)

Advanced configuration:
  -PI PROXY_IP, --proxy-ip PROXY_IP
                        Proxy IP.
  -PP PROXY_PORT, --proxy-port PROXY_PORT
                        Proxy port.
  -rt REQUEST_TIMEOUT, --request-timeout REQUEST_TIMEOUT
                        Set the timeout of HTTP requests.

Export results:
  --export-xlsx EXPORT_XLSX
                        Output XLSX file to store the results in.
  --export-json EXPORT_JSON
                        Output JSON file to store the results in.
  --export-sqlite EXPORT_SQLITE
                        Output SQLITE3 file to store the results in.

Tenants:
  -tf TENANTS_FILE, --tenants-file TENANTS_FILE
                        Path to file containing a line by line list of tenants names.
  -tt TENANT, --tenant TENANT
                        Tenant name.
  --stdin               Read targets from stdin. (default: False)
```

## Quick win commands

 + Find tenant ids from a list of domain read from a file:
    ```
    ./FindAzureDomainTenant.py -tf domains.txt
    ```

 + Find tenant ids from a list of domain read single options:
    ```
    ./FindAzureDomainTenant.py -tt example.com -tt mail.example.com
    ```

 + Find tenant ids read from stdin:
    ```
    subfinder -silent -d example.com | ./FindAzureDomainTenant.py --stdin
    ```
 
## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.