import mysql.connector
import os
import string
import random
from datetime import datetime
import qrcode
from PIL import Image

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

# Output directory for QR codes
output_dir = "coupon_data"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

def generate_coupon_code(length=8):
    """Generate a random coupon code."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def generate_qr_code(coupon_code, filename):
    """Generate a QR code for the coupon code and save it."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(coupon_code)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)

def main():
    try:
        # Connect to the database
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor(dictionary=True)

        # Fetch all coupons (or filter as needed)
        query = """
        SELECT id, coupon_code, qr_image
        FROM coupons
        WHERE deleted_at IS NULL
        """
        cursor.execute(query)
        coupons = cursor.fetchall()

        # Process each coupon
        for coupon in coupons:
            coupon_id = coupon["id"]
            
            # Generate a coupon code if not already present
            if not coupon["coupon_code"]:
                coupon_code = generate_coupon_code()
            else:
                coupon_code = coupon["coupon_code"]
                print(f"Coupon {coupon_id} already has a coupon code: {coupon_code}")

            # Generate QR code if not already present
            qr_filename = f"{output_dir}/coupon_{coupon_id}_qr.png"
            if not coupon["qr_image"] or not os.path.exists(qr_filename):
                generate_qr_code(coupon_code, qr_filename)
                qr_image_path = f"coupon_data/coupon_{coupon_id}_qr.png"
            else:
                qr_image_path = coupon["qr_image"]
                print(f"Coupon {coupon_id} already has a QR code: {qr_image_path}")

            # Update the database with the coupon code and QR image path
            update_query = """
            UPDATE coupons
            SET coupon_code = %s, qr_image = %s, updated_at = %s
            WHERE id = %s
            """
            cursor.execute(update_query, (coupon_code, qr_image_path, datetime.now(), coupon_id))
            print(f"Updated coupon {coupon_id} with code {coupon_code} and QR image {qr_image_path}")

    except mysql.connector.Error as e:
        print(f"Database error: {e}")
    finally:
        cursor.close()
        db.close()

if __name__ == "__main__":
    main()