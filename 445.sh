#!/bin/bash
# ===== CONFIG =====
DOMAIN="icare-wi.org"
USER="InternalPentest1"
PASS="Teq%MezewgKoy35"                # corrected password
TARGETS="targets.txt"
OUTDIR="smb_results"

SHARES=(
"SFTP-Proxy" "FCPFAX" "ITShared22" "ActData$" "ICARE_ACTDB-database"
"ExternalWebService" "Tester" "UploadImages" "SQL_Backup" "actinsight$"
"actpipeline$" "C" "MAIS" "cisco" "iCareADTools" "O365Offline"
"PSTs" "Software" "EDW" "InformationTechnology" "InpatientAuths"
"ITShared" "LDteam" "MCPSignoff" "MFD" "PA_Urgent_Fax_Requests"
"Processes" "shared" "Shared22" "SharedArchive" "STG-INPATIENTAUTHS"
"TCData" "TruCareLetters" "TruCareProdFeeds" "UpdateServicesPackages"
"WsusContent" "WebApps" "CPS"
)

mkdir -p $OUTDIR
echo "IP,Null,Anonymous,Guest,Creds,Writable" > $OUTDIR/summary.csv

# ===== LOOP =====
for ip in $(cat $TARGETS); do
    echo "==================== $ip ===================="

    mkdir -p $OUTDIR/$ip

    NULL="NO"
    ANON="NO"
    GUEST="NO"
    CREDS="NO"
    WRITE="NO"

    # ===== NULL SESSION =====
    netexec smb $ip -u '' -p '' | tee $OUTDIR/$ip/null.txt
    smbclient //$ip/IPC$ -N >> $OUTDIR/$ip/null.txt 2>&1

    if grep -q "[+]" $OUTDIR/$ip/null.txt; then
        NULL="YES"
    fi

    # ===== ANONYMOUS =====
    netexec smb $ip -u anonymous -p '' | tee $OUTDIR/$ip/anonymous.txt
    if grep -q "[+]" $OUTDIR/$ip/anonymous.txt; then
        ANON="YES"
    fi

    # ===== GUEST =====
    netexec smb $ip -u guest -p '' | tee $OUTDIR/$ip/guest.txt
    if grep -q "[+]" $OUTDIR/$ip/guest.txt; then
        GUEST="YES"
    fi

    # ===== CREDS ===== (WITH DOMAIN)
    netexec smb $ip -u $USER -p "$PASS" -d $DOMAIN --shares \
    | tee $OUTDIR/$ip/creds.txt

    if grep -q "[+]" $OUTDIR/$ip/creds.txt; then
        CREDS="YES"
    fi

    # ===== SMBCLIENT SHARE LIST (WITH DOMAIN) =====
    smbclient -L //$ip/ -U "$DOMAIN/$USER%$PASS" \
    | tee $OUTDIR/$ip/smbclient.txt

    # ===== ENUM4LINUX (SMART) =====
    if [[ "$NULL" == "YES" || "$ANON" == "YES" || "$GUEST" == "YES" || "$CREDS" == "YES" ]]; then
        enum4linux -a $ip | tee $OUTDIR/$ip/enum4linux.txt
    else
        echo "Skipping enum4linux (no access)" > $OUTDIR/$ip/enum4linux.txt
    fi

    # ===== SHARE TEST =====
    echo "test" > /tmp/test.txt

    for share in "${SHARES[@]}"; do
        echo "Testing //$ip/$share" >> $OUTDIR/$ip/share_test.txt

        # READ
        smbclient //$ip/$share -U "$DOMAIN/$USER%$PASS" -c "ls" \
        >> $OUTDIR/$ip/share_test.txt 2>&1

        # WRITE
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

done