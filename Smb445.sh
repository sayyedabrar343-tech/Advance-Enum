#!/bin/bash

DOMAIN="icare-wi.org"
USER="InternalPentest1"
PASS="Teq%MezewgKoy35"          # CORRECTED PASSWORD
TARGETS="targets.txt"
OUTDIR="smb_results"

mkdir -p $OUTDIR

for ip in $(cat $TARGETS); do
    echo "========== $ip =========="

    mkdir -p $OUTDIR/$ip

    # NULL SESSION (non-interactive)
    timeout 10 netexec smb $ip -u '' -p '' \
    | tee $OUTDIR/$ip/null.txt

    # SMBCLIENT NULL CHECK (NO FREEZE)
    timeout 10 smbclient //$ip/IPC$ -N -c "exit" \
    >> $OUTDIR/$ip/null.txt 2>&1

    # ANONYMOUS
    timeout 10 netexec smb $ip -u anonymous -p '' \
    | tee $OUTDIR/$ip/anonymous.txt

    # GUEST
    timeout 10 netexec smb $ip -u guest -p '' \
    | tee $OUTDIR/$ip/guest.txt

    # CREDS
    timeout 10 netexec smb $ip -u $USER -p "$PASS" -d $DOMAIN --shares \
    | tee $OUTDIR/$ip/creds.txt

    # SMBCLIENT LIST (NO INTERACTIVE)
    timeout 10 smbclient -L //$ip/ -U "$DOMAIN/$USER%$PASS" -c "exit" \
    | tee $OUTDIR/$ip/smbclient.txt

    # ENUM4LINUX (optional safe)
    timeout 20 enum4linux -a $ip \
    | tee $OUTDIR/$ip/enum4linux.txt

    echo "Done: $ip"
    echo ""

done