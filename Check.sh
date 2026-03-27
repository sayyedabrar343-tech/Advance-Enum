# Create a test script
cat > test_scan.sh << 'EOF'
#!/bin/bash
echo "=== Test Script Running ==="
echo "Current directory: $(pwd)"
echo "open_ports exists? $([ -d open_ports ] && echo YES || echo NO)"
if [[ -d open_ports ]]; then
    echo "Port folders:"
    for port_dir in open_ports/*/; do
        echo "  - $(basename "$port_dir")"
        for ip_dir in "$port_dir"*/; do
            echo "      IP: $(basename "$ip_dir")"
        done
    done
else
    echo "open_ports not found"
fi
EOF

chmod +x test_scan.sh
./test_scan.sh