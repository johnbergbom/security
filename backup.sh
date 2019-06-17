#!/bin/bash
#
# Very simple backup script created by John. There is very little space
# on the hosted VM, and rsync creates a parallel file in the processing.
# Therefore files are split into chunks of 100 megabytes.

TMP_DIR="/var/tmp/backup"
LARGE_TMP_DIR=$1
HOSTEDVM=$2
DEST=$HOSTEDVM:/backup

rm -rf "$TMP_DIR"
mkdir "$TMP_DIR"
rm -rf "$LARGE_TMP_DIR"
mkdir "$LARGE_TMP_DIR"
#cd "$TMP_DIR"

#function backup(directory,extra_tar_params) {
function backup() {
  directory=$1
  extra_tar_params=$2

  # Check how much space we need for handling this directory
  TAKES_SPACE=$(du -BK -s "$directory"|awk '{ print $1 }'|sed 's/K$//')
  NEEDED_FREE_SPACE=$(echo "$TAKES_SPACE*2 + 102400"|bc)
  #echo "FREE SPACE: $FREE_SPACE, directory: $directory, TAKES_SPACE: $TAKES_SPACE, NEEDED_FREE_SPACE: $NEEDED_FREE_SPACE"

  # Figure out what directory to use for the temporary files.
  # Use the local hard drive if it has enough empty space,
  # otherwise use the external drive.
  if [ $NEEDED_FREE_SPACE -lt $FREE_SPACE ]; then
    echo "Enough room in $TMP_DIR for temporary files when backing up $directory"
    cd "$TMP_DIR"
  else
    if df | grep -q "/mnt/large_drive"; then
      echo "Using $LARGE_TMP_DIR for temporary files when backing up $directory"
      cd "$LARGE_TMP_DIR"
    else
      echo "SKIPPING BACKUP OF $directory BECAUSE LARGE DRIVE IS NOT MOUNTED."
      return
    fi
  fi

  # Do the actual backup
  tarball=$(echo "$directory" | sed 's/^\///' | sed 's/\//_/g').tar
  echo "$(date '+%Y-%m-%d %H:%M:%S'): Making packet $directory as $tarball"
  tar -cf "$tarball" $extra_tar_params "$directory" &> /dev/null
  echo "$(date '+%Y-%m-%d %H:%M:%S'): Splitting $tarball"
  split -a 3 -b 100M -d "$tarball" "$tarball"
  rm "$tarball"
  echo "$(date '+%Y-%m-%d %H:%M:%S'): Rsyncing $tarball"
  rsync "${tarball}"* "$DEST"
  echo "$(date '+%Y-%m-%d %H:%M:%S'): done with rsync of $tarball"
  rm "${tarball}"*
}

echo "$(date '+%Y-%m-%d %H:%M:%S'): Starting new run"

# Calculate how much free space that exists in the root partition
# that we can play with
FREE_SPACE=$(df -BK|grep /$|awk '{ print $4 }'|sed 's/K$//')

backup dir1 ""
backup dir2 ""
backup /etc ""
ssh "$HOSTEDVM" chmod go= /backup/etc.tar*
backup /usr/local/bin ""
# Skip some large VM images due to space limitations at the hosted VM
backup dir3 "--exclude /some/path/with/large/files"

# Backup home sensor databases at raspberry pi:
echo "$(date '+%Y-%m-%d %H:%M:%S'): Backing up home sensor databases at raspberry pi"
cd "$TMP_DIR"
scp raspberrypi:/var/lib/openhab2/home_sensors_sqlite.db .
scp raspberrypi:/home_sensors/home_sensor_alerts_sqlite.db .
scp raspberrypi:/home_sensors/sms_sending.db .
tar -cf home_sensor_databases.tar home_sensors_sqlite.db home_sensor_alerts_sqlite.db sms_sending.db &> /dev/null
echo "$(date '+%Y-%m-%d %H:%M:%S'): Copying home sensor databases to hosted VM"
scp home_sensor_databases.tar "$DEST"
echo "$(date '+%Y-%m-%d %H:%M:%S'): done backing up home sensor databases"
rm home_sensor_databases.tar home_sensors_sqlite.db home_sensor_alerts_sqlite.db sms_sending.db

# Backup things on hosted VM:
echo "$(date '+%Y-%m-%d %H:%M:%S'): backing up some database at hosted VM"
rm -f /backup_hosted_vm/db_dump.psql.tmp
ssh -T "$HOSTEDVM" pg_dump -F c -b -U dbuser dbname > /backup_hosted_vm/db_dump.psql.tmp
rm -f /backup_hosted_vm/db_dump.psql
mv /backup_hosted_vm/db_dump.psql.tmp /backup_hosted_vm/db_dump.psql
echo "$(date '+%Y-%m-%d %H:%M:%S'): done backing up some database at hosted VM"

echo "$(date '+%Y-%m-%d %H:%M:%S'): backing up other things at hosted VM"
ssh -t -t "$HOSTEDVM" sudo /usr/local/bin/backup.sh > /dev/null
scp "$DEST"/hosted_vm_etc.tar /backup_hosted_vm/etc.tar
chmod go= /backup_hosted_vm/etc.tar
scp "$DEST"/hosted_vm_usr_local_bin.tar //backup_hosted_vm/usr_local_bin.tar

chown someuser:someuser /backup_hosted_vm/*
echo "$(date '+%Y-%m-%d %H:%M:%S'): done backing up other things at hosted VM"


#Clean up
rm -rf "$TMP_DIR"
rm -rf "$LARGE_TMP_DIR"

