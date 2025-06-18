import mysql.connector
import json

# Database configuration (same as in app.py)
db_config = {
    'host': 'localhost',
    'port': '3306',
    'user': 'root',
    'password': 'root',
    'database': 'coupon',
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci',
    'autocommit': True
}

def main():
    try:
        # Connect to the database
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor(dictionary=True)

        # Fetch all coupons with related data
        query = """
        SELECT c.*, cat.name_en AS category_name_en
        FROM coupons c
        LEFT JOIN categories cat ON c.category_id = cat.id
        WHERE c.deleted_at IS NULL
        """
        cursor.execute(query)
        coupons = cursor.fetchall()

        # Convert to JSON-friendly format
        coupon_data = []
        for coupon in coupons:
            coupon_data.append({
                'id': coupon['id'],
                'name_en': coupon['name_en'],
                'name_cn': coupon['name_cn'],
                'category_name_en': coupon['category_name_en'],
                'percentage': float(coupon['percentage']) if coupon['percentage'] else 0,
                'quantity': coupon['quantity'],
                'status': coupon['status'],
                'expiry_date': str(coupon['expiry_date']) if coupon['expiry_date'] else None,
                'coupon_code': coupon['coupon_code'],
                'qr_image': coupon['qr_image']
            })

        # Save to JSON file
        with open('coupons.json', 'w', encoding='utf-8') as f:
            json.dump(coupon_data, f, ensure_ascii=False, indent=4)
        print("Coupons extracted to coupons.json")

    except mysql.connector.Error as e:
        print(f"Database error: {e}")
    finally:
        cursor.close()
        db.close()

if __name__ == "__main__":
    main()