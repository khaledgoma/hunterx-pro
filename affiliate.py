#!/usr/bin/env python3
"""Affiliate Tracking System for HunterX Enterprise"""
import os, json, hashlib
from datetime import datetime

AFFILIATE_FILE = os.path.expanduser('~/hunterx/web_dashboard/affiliates.json')
CLICKS_FILE = os.path.expanduser('~/hunterx/web_dashboard/clicks.json')

def init():
    if not os.path.exists(AFFILIATE_FILE):
        with open(AFFILIATE_FILE, 'w') as f:
            json.dump({}, f)
    if not os.path.exists(CLICKS_FILE):
        with open(CLICKS_FILE, 'w') as f:
            json.dump([], f)

def generate_affiliate_link(partner_name, commission_rate=25):
    init()
    with open(AFFILIATE_FILE) as f:
        affiliates = json.load(f)
    partner_id = hashlib.md5(partner_name.encode()).hexdigest()[:8]
    affiliates[partner_id] = {
        'name': partner_name,
        'commission': commission_rate,
        'joined': datetime.now().strftime('%Y-%m-%d'),
        'clicks': 0,
        'conversions': 0,
        'earnings': 0
    }
    with open(AFFILIATE_FILE, 'w') as f:
        json.dump(affiliates, f, indent=2)
    return f"http://localhost:5000/landing?ref={partner_id}"

def track_click(ref_id):
    init()
    with open(AFFILIATE_FILE) as f:
        affiliates = json.load(f)
    if ref_id in affiliates:
        affiliates[ref_id]['clicks'] += 1
        with open(AFFILIATE_FILE, 'w') as f:
            json.dump(affiliates, f, indent=2)

def record_conversion(ref_id, amount):
    init()
    with open(AFFILIATE_FILE) as f:
        affiliates = json.load(f)
    if ref_id in affiliates:
        commission = amount * (affiliates[ref_id]['commission'] / 100)
        affiliates[ref_id]['conversions'] += 1
        affiliates[ref_id]['earnings'] += commission
        with open(AFFILIATE_FILE, 'w') as f:
            json.dump(affiliates, f, indent=2)
        return affiliates[ref_id]
    return None

def get_stats(ref_id):
    init()
    with open(AFFILIATE_FILE) as f:
        affiliates = json.load(f)
    return affiliates.get(ref_id, None)

if __name__ == '__main__':
    init()
    link = generate_affiliate_link("DemoPartner", 30)
    print(f"Affiliate Link: {link}")
    print("Stats:", get_stats(link.split('=')[-1]))

