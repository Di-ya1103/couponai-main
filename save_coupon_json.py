import json
import os

# Define the coupon data (as provided)
coupon_data = [
    {
        "id": 669,
        "coupon_id": "NjY5",
        "popular_coupon_order": 0,
        "name": None,
        "coupon_name": "Coupon 535",
        "description": None,
        "additional_terms": "消息出示",
        "type": "Gift",
        "cash_amount": None,
        "percentage": None,
        "gift1": "免費神諭牌/塔羅牌諮詢",
        "gift2": None,
        "is_coupon_none": 1,
        "amount": 0,
        "coupon_amount": "凡惠顧本店",
        "is_specific_item": "1",
        "when_purchasing": None,
        "regular_price": 0,
        "discount_price": 0,
        "purchasing_amount": 0,
        "points_for_redeem": 0,
        "quantity": 0,
        "qr_image": "",
        "coupon_code": "",
        "image": "https://redsparkte.a2hosted.com/coupon_go_v2/storage/app/public/images/merchant/796/coupons/673d5e0700d89.jpg",
        "offer_image": "",
        "category_id": 59,
        "category_name": "教育&工作坊",
        "color": "#34b7b3",
        "branch_id": 0,
        "branch_parent": 0,
        "vendor_id": 796,
        "vendor_name": "Spicy banana.oil",
        "vendor_profile": "https://redsparkte.a2hosted.com/coupon_go_v2/storage/app/public/images/merchant/796/logo/673d5ca66cd6c.jpeg",
        "vendor_country": None,
        "vendor_state": None,
        "vendor_city": None,
        "vendor_street_address": "新界荃灣蕙荃路22-66號1G17鋪",
        "vendor_latitude": None,
        "vendor_longitude": None,
        "distance": None,
        "is_scan_limit_reached": False,
        "is_coupon_favorite": 0,
        "is_shop_favorite": 0,
        "is_coupon_used": 0,
        "is_limited_notification": 0,
        "status": "Approved",
        "expiry_date": "2025-12-10",
        "expiry_time": "11:51:00",
        "created_at": "2024-11-20 11:52:19",
        "remaining_qr_code": 6,
        "coupon_offer_text": "免費神諭牌/塔羅牌諮詢現金券",
        "coupon_short_description": "消費 “即享“免費免費神諭牌/塔羅牌諮詢",
        "branch_count": 0,
        "has_branch": 0
    }
]

# Define the path to save the JSON file
output_dir = "coupon_data"
os.makedirs(output_dir, exist_ok=True)  # Create directory if it doesn't exist
output_file = os.path.join(output_dir, "coupon_535.json")

# Write the JSON data to a file
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(coupon_data, f, ensure_ascii=False, indent=4)

print(f"JSON file saved as {output_file}")