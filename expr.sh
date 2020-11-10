#!/bin/sh

while read p; do
	build/src/.libs/ancygibitest $p >> res.csv
done < gmc.list
