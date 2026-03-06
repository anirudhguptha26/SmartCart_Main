import sqlite3

DATABASE = 'smartcart.db'


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS admin (
            admin_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL,
            email         TEXT    UNIQUE NOT NULL,
            password      TEXT    NOT NULL,
            profile_image TEXT    DEFAULT NULL,
            is_approved   INTEGER DEFAULT 0,
            is_super_admin INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS admin_requests (
            request_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            email        TEXT UNIQUE NOT NULL,
            password     TEXT NOT NULL,
            status       TEXT DEFAULT 'pending',
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id  INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            email    TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone    TEXT DEFAULT NULL,
            address  TEXT DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS products (
            product_id  INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            description TEXT    DEFAULT NULL,
            category    TEXT    DEFAULT NULL,
            price       REAL    NOT NULL,
            image       TEXT    DEFAULT NULL,
            quantity    INTEGER DEFAULT 0,
            added_by_admin INTEGER DEFAULT NULL,
            FOREIGN KEY (added_by_admin) REFERENCES admin(admin_id)
        );

        CREATE TABLE IF NOT EXISTS orders (
            order_id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id              INTEGER NOT NULL,
            razorpay_order_id    TEXT    DEFAULT NULL,
            razorpay_payment_id  TEXT    DEFAULT NULL,
            amount               REAL    NOT NULL,
            payment_status       TEXT    DEFAULT 'pending',
            delivery_address     TEXT    DEFAULT NULL,
            created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );

        CREATE TABLE IF NOT EXISTS order_items (
            item_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id     INTEGER NOT NULL,
            product_id   INTEGER DEFAULT NULL,
            product_name TEXT    NOT NULL,
            quantity     INTEGER NOT NULL,
            price        REAL    NOT NULL,
            FOREIGN KEY (order_id)   REFERENCES orders(order_id),
            FOREIGN KEY (product_id) REFERENCES products(product_id)
        );
    """)

    # Ensure columns exist for upgrades
    try:
        cursor.execute("ALTER TABLE admin ADD COLUMN is_approved INTEGER DEFAULT 0")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE admin ADD COLUMN is_super_admin INTEGER DEFAULT 0")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE products ADD COLUMN quantity INTEGER DEFAULT 0")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE products ADD COLUMN added_by_admin INTEGER DEFAULT NULL")
    except:
        pass

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")


if __name__ == '__main__':
    init_db()