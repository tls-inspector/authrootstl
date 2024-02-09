#!/bin/bash
set -e

rm -f new.cab
curl -L https://aka.ms/ctldownload > new.cab
cabextract new.cab
rm new.cab