#!/bin/bash

for dir in open_ports/*/; do
    port=$(basename "$dir")
    output_file="${dir}${port}.txt"

    # clear file
    > "$output_file"

    # read all files inside that port folder
    for file in "$dir"*; do
        if [ -f "$file" ]; then
            grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" >> "$output_file"
        fi
    done

    # remove duplicates
    sort -u -o "$output_file" "$output_file"

    echo "Done for port $port → $output_file"
done