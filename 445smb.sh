#!/bin/bash

# ===== CONFIG =====
DOMAIN="icare-wi.org"
USER="InternalPentest1"
PASS="Teq%MezewgKoy35"          # corrected password
TARGETS="targets.txt"
OUTDIR="smb_results"

# Only these shares will be tested (add or remove as needed)
SHARES=(
    "ITShared32"                # example – change or add more shares here
)

mkdir -p $OUTDIR

# CSV summary header
echo "IP,Null,Anonymous,Guest,Creds,Writable" > $OUTDIR/summary.csv

for ip in $(cat $TARGETS); do
    echo "========== $ip =========="

    mkdir -p $OUTDIR/$ip

    NULL="NO"
    ANON="NO"
    GUEST="NO"
    CREDS="NO"
    WRITE="NO"

    # ===== NULL SESSION =====
    timeout 10 netexec smb $ip -u '' -p '' \
    | tee $OUTDIR/$ip/null.txt

    timeout 10 smbclient //$ip/IPC$ -N -c "exit" \
    >> $OUTDIR/$ip/null.txt 2>&1

    if grep -q "[+]" $OUTDIR/$ip/null.txt; then
        NULL="YES"
    fi

    # ===== ANONYMOUS =====
    timeout 10 netexec smb $ip -u anonymous -p '' \
    | tee $OUTDIR/$ip/anonymous.txt

    if grep -q "[+]" $OUTDIR/$ip/anonymous.txt; then
        ANON="YES"
    fi

    # ===== GUEST =====
    timeout 10 netexec smb $ip -u guest -p '' \
    | tee $OUTDIR/$ip/guest.txt

    if grep -q "[+]" $OUTDIR/$ip/guest.txt; then
        GUEST="YES"
    fi

    # ===== CREDS (with domain) =====
    timeout 10 netexec smb $ip -u $USER -p "$PASS" -d $DOMAIN --shares \
    | tee $OUTDIR/$ip/creds.txt

    if grep -q "[+]" $OUTDIR/$ip/creds.txt; then
        CREDS="YES"
    fi

    # ===== SMBCLIENT SHARE LIST (with credentials) =====
    timeout 10 smbclient -L //$ip/ -U "$DOMAIN/$USER%$PASS" -c "exit" \
    | tee $OUTDIR/$ip/smbclient.txt

    # ===== ENUM4LINUX (smart – only if any access) =====
    if [[ "$NULL" == "YES" || "$ANON" == "YES" || "$GUEST" == "YES" || "$CREDS" == "YES" ]]; then
        timeout 20 enum4linux -a $ip \
        | tee $OUTDIR/$ip/enum4linux.txt
    else
        echo "Skipping enum4linux (no access)" > $OUTDIR/$ip/enum4linux.txt
    fi

    # ===== SHARE TEST (only the shares listed above) =====
    echo "test" > /tmp/test.txt

    for share in "${SHARES[@]}"; do
        echo "Testing //$ip/$share" >> $OUTDIR/$ip/share_test.txt

        # READ test
        smbclient //$ip/$share -U "$DOMAIN/$USER%$PASS" -c "ls" \
        >> $OUTDIR/$ip/share_test.txt 2>&1

        # WRITE test
        smbclient //$ip/$share -U "$DOMAIN/$USER%$PASS" \
        -c "put /tmp/test.txt test.txt" \
        >> $OUTDIR/$ip/share_test.txt 2>&1

        if grep -q "putting file" $OUTDIR/$ip/share_test.txt; then
            WRITE="YES"
        fi
    done

    # ===== SUMMARY =====
    echo "$ip,$NULL,$ANON,$GUEST,$CREDS,$WRITE" \
    >> $OUTDIR/summary.csv

    echo "Done: $ip"
    echo ""

done