"""
Attack simulation scripts using Mininet.
Simulates DDoS, Port Scan, Brute Force, DNS Tunneling attacks.
Run with: sudo python3 simulation/attack_simulator.py
"""
import sys
import time
import subprocess
sys.path.insert(0, '/home/nitish/network-threat-detection')

from mininet.log import setLogLevel
from simulation.network_topology import create_topology

def wait_and_print(msg, seconds=3):
    print(f"\n⏳ {msg} (waiting {seconds}s for detection)...")
    time.sleep(seconds)

def run_ddos_simulation(attacker, victim):
    print("\n" + "="*60)
    print("🚨 ATTACK 1: DDoS Simulation")
    print("="*60)
    print(f"   Attacker: {attacker.IP()} → Victim: {victim.IP()}")
    print("   Method: hping3 UDP flood")

    # hping3 UDP flood — sends massive packets
    attacker.cmd(
        f'hping3 --udp -p 80 --flood --rand-source {victim.IP()} &'
    )
    wait_and_print("DDoS flood running — check dashboard for CRITICAL alert", 8)

    # Stop attack
    attacker.cmd('pkill hping3')
    print("✅ DDoS attack stopped")

def run_port_scan_simulation(attacker, victim):
    print("\n" + "="*60)
    print("🚨 ATTACK 2: Port Scan Simulation")
    print("="*60)
    print(f"   Attacker: {attacker.IP()} → Victim: {victim.IP()}")
    print("   Method: nmap aggressive scan")

    # nmap SYN scan across all ports
    result = attacker.cmd(
        f'nmap -sS -p 1-1000 --min-rate 500 {victim.IP()} 2>&1'
    )
    print(f"   nmap result: {result[:200]}...")
    wait_and_print("Port scan running — check dashboard for HIGH alert", 5)
    print("✅ Port scan complete")

def run_brute_force_simulation(attacker, server):
    print("\n" + "="*60)
    print("🚨 ATTACK 3: Brute Force Simulation")
    print("="*60)
    print(f"   Attacker: {attacker.IP()} → Server: {server.IP()}:22")
    print("   Method: hping3 SYN flood on SSH port")

    # SYN flood on port 22 (SSH brute force pattern)
    attacker.cmd(
        f'hping3 -S -p 22 --flood {server.IP()} &'
    )
    wait_and_print("Brute force running — check dashboard for HIGH alert", 8)

    attacker.cmd('pkill hping3')
    print("✅ Brute force attack stopped")

def run_dns_tunneling_simulation(attacker, victim):
    print("\n" + "="*60)
    print("🚨 ATTACK 4: DNS Tunneling Simulation")
    print("="*60)
    print(f"   Attacker: {attacker.IP()} → Victim: {victim.IP()}")
    print("   Method: Large DNS query payloads via hping3")

    # Send oversized DNS packets (port 53)
    attacker.cmd(
        f'hping3 --udp -p 53 -d 512 --flood {victim.IP()} &'
    )
    wait_and_print("DNS tunneling running — check dashboard for HIGH alert", 6)

    attacker.cmd('pkill hping3')
    print("✅ DNS tunneling attack stopped")

def run_all_simulations():
    print("\n🛡️  CCNCS Network Threat Detection — Attack Simulation")
    print("="*60)
    print("Make sure packet_capture.py is running in another terminal!")
    print("="*60)

    input("\n▶️  Press ENTER to start simulation...")

    net, attacker, victim, monitor, server = create_topology()

    try:
        # Test connectivity first
        print("\n🔍 Testing network connectivity...")
        result = attacker.cmd(f'ping -c 2 {victim.IP()}')
        if "2 received" in result or "1 received" in result:
            print("✅ Network connectivity OK!")
        else:
            print("⚠️  Connectivity issue but continuing...")

        # Run all attacks one by one
        run_ddos_simulation(attacker, victim)
        time.sleep(3)

        run_port_scan_simulation(attacker, victim)
        time.sleep(3)

        run_brute_force_simulation(attacker, server)
        time.sleep(3)

        run_dns_tunneling_simulation(attacker, victim)
        time.sleep(3)

        print("\n" + "="*60)
        print("🎉 ALL ATTACK SIMULATIONS COMPLETE!")
        print("="*60)
        print("\n📊 Check your dashboard at http://localhost:3000")
        print("   You should see alerts for:")
        print("   🔴 DDoS        — CRITICAL (T1498)")
        print("   🟠 Port Scan   — HIGH     (T1046)")
        print("   🟠 Brute Force — HIGH     (T1110)")
        print("   🟠 DNS Tunnel  — HIGH     (T1071)")

        # Optional: open Mininet CLI for manual testing
        answer = input("\n🖥️  Open Mininet CLI for manual testing? (y/n): ")
        if answer.lower() == 'y':
            CLI(net)

    except KeyboardInterrupt:
        print("\n⚠️  Simulation interrupted")
    finally:
        print("\n🧹 Cleaning up network...")
        net.stop()
        subprocess.run(['mn', '--clean'], capture_output=True)
        print("✅ Cleanup complete!")

if __name__ == "__main__":
    run_all_simulations()
