#!/bin/bash
TARGET="10.2.2.191"   # ← your actual machine IP from ip addr show

echo "🛡️  CCNCS Attack Simulation"
echo "Target: $TARGET"
echo "Make sure packet_capture.py is running!"
echo ""

# ── Attack 1: DDoS ──
echo "🚨 Attack 1: DDoS Flood (10 seconds)..."
sudo hping3 --udp -p 80 --flood $TARGET &
HPING_PID=$!
sleep 10
sudo kill $HPING_PID 2>/dev/null
echo "✅ DDoS stopped — check dashboard for CRITICAL T1498"
sleep 5

# ── Attack 2: Port Scan ──
echo ""
echo "🚨 Attack 2: Port Scan..."
sudo nmap -sS -p 1-500 --min-rate 500 $TARGET
echo "✅ Port scan complete — check dashboard for HIGH T1046"
sleep 5

# ── Attack 3: Brute Force ──
echo ""
echo "🚨 Attack 3: Brute Force (8 seconds)..."
sudo hping3 -S -p 22 --flood $TARGET &
HPING_PID=$!
sleep 8
sudo kill $HPING_PID 2>/dev/null
echo "✅ Brute force stopped — check dashboard for HIGH T1110"
sleep 5

# ── Attack 4: DNS Tunneling ──
echo ""
echo "🚨 Attack 4: DNS Tunneling (6 seconds)..."
sudo hping3 --udp -p 53 -d 512 --flood $TARGET &
HPING_PID=$!
sleep 6
sudo kill $HPING_PID 2>/dev/null
echo "✅ DNS tunneling stopped — check dashboard for HIGH T1071"

echo ""
echo "🎉 All attacks complete! Check http://localhost:3000"
