#!/usr/bin/env bash

# The user's home directory must contain .pgpass file. 
# For more about it see here https://www.postgresql.org/docs/10/libpq-pgpass.html
set -o errexit
set -o nounset
set -o pipefail

PGHOST=$1
PGUSER=$2
BKP_PATH=$3/$(date "+%Y%m%d")
TIME_SAVE_BKP=${1:-25} # default 25 days for save backups
echo "Days for save backups is $TIME_SAVE_BKP"
DATE_SAVE_BKP=$(date -d "-$TIME_SAVE_BKP day" +"%Y%m%d")
echo "Backups older then $DATE_SAVE_BKP will deleted"
START_TIME=$(date "+%Y%m%d %H:%M")
echo "Starting backup $PGHOST to $BKP_PATH"
time pg_basebackup -h "$PGHOST" -U "$PGUSER" -D "$BKP_PATH" -Ft -z -Xs -P
END_TIME=$(date "+%Y%m%d %H:%M")
printf "Backup finished. \n Start time is %s \nEnd time is %s \n\n\n", "$START_TIME", "$END_TIME"
echo "Starting copy backup to S3 bucket"
time s3cmd put -r --progress --multipart-chunk-size-mb 200 -v "$BKP_PATH" s3://sb-backup/"$PGHOST"/
echo "Backup successful copy to S3 bucket"
rm -rf "$BKP_PATH"
echo "Backup $BKP_PATH was removed from local disk"

dirs_list=$(s3cmd ls s3://sb-backup/db1/ | grep DIR | sed -E 's|.*/(20[0-9]{6}})/|\1|')
for bkp_name in $dirs_list;
  do
    if [ "$bkp_name" -lt "$DATE_SAVE_BKP" ]
    then
      s3cmd del -r --progress s3://sb-backup/"$PGHOST"/"$bkp_name"
      echo "Backup $bkp_name was deleted"
    fi
done
