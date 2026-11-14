#!/usr/bin/env python3

import json
import os

def test_discord_webhook():
    print("=" * 60)
    print("SPEEDPOT v1.5 - DISCORD WEBHOOK TEST")
    print("=" * 60)
    
    # Step 1: Check config.json
    print("\n[1] Checking config.json...")
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(project_root, 'config.json')
    
    if not os.path.exists(config_path):
        print("    ERROR: config.json not found!")
        return
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    alerts_config = config.get("ALERTS", {})
    
    print(f"    ALERTS.ENABLED: {alerts_config.get('ENABLED', False)}")
    print(f"    ALERTS.DISCORD.enabled: {alerts_config.get('DISCORD', {}).get('enabled', False)}")
    
    webhook_url = alerts_config.get('DISCORD', {}).get('webhook_url', '')
    print(f"    ALERTS.DISCORD.webhook_url: {'SET (' + webhook_url[:50] + '...)' if webhook_url else 'NOT SET'}")
    
    # Step 2: Check requirements
    print("\n[2] Checking requirements...")
    try:
        import requests
        print("    requests library: OK")
    except ImportError:
        print("    ERROR: requests library not installed!")
        print("    Run: pip install requests")
        return
    
    # Step 3: Test direct webhook
    if webhook_url:
        print("\n[3] Testing webhook directly...")
        
        test_payload = {
            "embeds": [{
                "title": "[Speedpot] Direct Test",
                "description": "This is a direct test bypassing AlertManager",
                "color": 0x00ff00,
                "footer": {"text": "If you see this, your webhook works!"}
            }]
        }
        
        try:
            response = requests.post(webhook_url, json=test_payload, timeout=10)
            print(f"    Response status: {response.status_code}")
            
            if response.status_code == 204:
                print("    SUCCESS! Check your Discord channel.")
            else:
                print(f"    ERROR: Unexpected status code")
                print(f"    Response: {response.text}")
        except Exception as e:
            print(f"    ERROR: {e}")
    else:
        print("\n[3] Skipping direct test - no webhook URL configured")
    
    # Step 4: Test via AlertManager
    print("\n[4] Testing via AlertManager...")
    
    from alerts import AlertManager
    
    # Create AlertManager (will auto-load from config.json)
    am = AlertManager()
    
    print(f"    AlertManager.enabled: {am.enabled}")
    print(f"    Discord config in AlertManager: {am.config.get('DISCORD', {})}")
    
    # Run test_alerts
    print("\n[5] Running test_alerts()...")
    results = am.test_alerts(verbose=True)
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    
    if results.get("success"):
        print("\nSUCCESS! Check your Discord channel for the test message.")
    else:
        print("\nFAILED. Common issues:")
        print("  1. ALERTS.ENABLED is false in config.json")
        print("  2. ALERTS.DISCORD.enabled is false in config.json")
        print("  3. ALERTS.DISCORD.webhook_url is empty or invalid")
        print("  4. Webhook URL is malformed (should start with https://discord.com/api/webhooks/)")
        print("\nCheck your config.json file and ensure:")
        print('  "ALERTS": {')
        print('    "ENABLED": true,')
        print('    "DISCORD": {')
        print('      "enabled": true,')
        print('      "webhook_url": "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"')
        print('    }')
        print('  }')


if __name__ == "__main__":
    test_discord_webhook()
