# Simple TCP Port Scanner
![Static Badge](https://img.shields.io/badge/Go-100%25-brightgreen)
## Description

Scan TCP Port Fast

Just For Education


## Table of Contents 


- [Installation](#installation)
- [Usage](#usage)


## Installation

```
go install github.com/destan0098/SimplePortScanner/cmd/PortScanner@latest
```
or use
```
git clone https://github.com/destan0098/SimplePortScanner.git

```

## Usage

To Run Enter Below Code
For Use This Enter Website without http  In Input File
Like : google.com

```
PortScanner -d 185.143.233.51 -r "1-65535" -w 1800 -t 150
```
or for Help
```
PortScanner -h 

```

```
NAME:
   PortScanner.exe - A new cli application

USAGE:
   PortScanner.exe [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --ip value, -d value         Enter just one IP
   --CIDR value, -c value       Enter just one CIDR
   --list value, -l value       Enter a list from a text file
   --pipe, -p                   Enter just from a pipeline (default: false)
   --PortRange value, -r value  Enter Port
   --output value, -o value     Save in File 1 for text , 2 for csv , 3 for json and 4 for all (default: 0)
   --timeout value, -t value    Time out Port Scanning in millisecond  (default: 500)
   --filename value, -f value   output file name
   --worker value, -w value     Default Value is 300 (default: 300)
   --help, -h                   show help


```




---



## Features

this tool check tcp open ports status very fast


